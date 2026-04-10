#!/usr/bin/env node
/**
 * TarantuBench Evaluation Harness
 *
 * Boots labs from the dataset JSONL, instruments all HTTP traffic via a
 * transparent proxy, validates flag submissions, and produces structured
 * per-lab JSON reports.
 *
 * Usage:
 *   node harness.js --dataset <path-to-jsonl> [options]
 *
 * Modes:
 *   --command <cmd>   Callback mode: run <cmd> for each lab ({URL} is replaced)
 *   --mode server     Server mode: print URL and wait for flag / timeout
 *
 * Options:
 *   --timeout <s>     Per-lab timeout in seconds (default 300)
 *   --labs <a,b,...>  Only run specific lab IDs
 *   --port <n>        Base port for proxy servers (default 4100)
 *   --max-concurrent <n>  Parallel labs in callback mode (default 1)
 *   --output <dir>    Results directory (default ./results)
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, execSync } from 'node:child_process';
import crypto from 'node:crypto';
import os from 'node:os';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── CLI ────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    dataset: null,
    command: null,
    mode: 'callback',
    timeout: 300,
    labs: null,
    port: 4100,
    maxConcurrent: 1,
    output: path.join(__dirname, 'results'),
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dataset' && args[i + 1]) opts.dataset = args[++i];
    if (args[i] === '--command' && args[i + 1]) opts.command = args[++i];
    if (args[i] === '--mode' && args[i + 1]) opts.mode = args[++i];
    if (args[i] === '--timeout') opts.timeout = parseInt(args[++i], 10);
    if (args[i] === '--labs' && args[i + 1]) opts.labs = args[++i].split(',');
    if (args[i] === '--port') opts.port = parseInt(args[++i], 10);
    if (args[i] === '--max-concurrent') opts.maxConcurrent = parseInt(args[++i], 10);
    if (args[i] === '--output' && args[i + 1]) opts.output = args[++i];
  }
  if (!opts.command && opts.mode === 'callback') opts.mode = 'server';
  return opts;
}

// ── Dataset loading ────────────────────────────────────────────────

function loadDataset(filepath) {
  const lines = fs.readFileSync(filepath, 'utf-8').trim().split('\n');
  return lines.map(line => JSON.parse(line));
}

// ── Lab server boot ────────────────────────────────────────────────

async function pollServer(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(url, { signal: AbortSignal.timeout(1000) });
      return true;
    } catch { /* not ready */ }
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

async function bootLab(row, labPort) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `tarantubench-${row.lab_id}-`));

  const deps = typeof row.dependencies === 'string'
    ? JSON.parse(row.dependencies)
    : (row.dependencies || {});

  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
    name: row.lab_id,
    type: 'module',
    dependencies: deps,
  }, null, 2));

  let src = row.server_code;
  src = src.replace(/\.listen\(3000/g, `.listen(${labPort}`);
  fs.writeFileSync(path.join(tmpDir, 'server.js'), src);

  const flag = `TARANTU{${crypto.randomBytes(16).toString('hex')}}`;
  fs.writeFileSync(path.join(tmpDir, '.flag'), flag);

  execSync('npm install --silent', { cwd: tmpDir, stdio: 'pipe', timeout: 60000 });

  const proc = spawn('node', ['server.js'], {
    cwd: tmpDir,
    env: { ...process.env, PORT: String(labPort) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const ready = await pollServer(`http://127.0.0.1:${labPort}/`, 30000);
  if (!ready) {
    proc.kill('SIGTERM');
    throw new Error(`Lab ${row.lab_id} failed to start on port ${labPort}`);
  }

  return { proc, tmpDir, flag };
}

function killLab(proc, tmpDir) {
  if (proc && !proc.killed) {
    proc.kill('SIGTERM');
    setTimeout(() => { if (!proc.killed) proc.kill('SIGKILL'); }, 2000);
  }
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
}

// ── Logging proxy ──────────────────────────────────────────────────

function createMetrics(row) {
  return {
    lab_id: row.lab_id,
    title: row.title,
    difficulty: row.difficulty,
    category: row.category,
    vuln_subtype: row.vuln_subtype || null,
    chain_type: row.chain_type || null,
    solved: false,
    wall_time_ms: 0,
    http_requests: 0,
    flag_attempts: [],
    time_to_solve_ms: null,
    unique_paths: new Set(),
    http_log: [],
    error: null,
    startTime: null,
  };
}

function handleFlagSubmission(req, res, flag, metrics) {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    try {
      const parsed = JSON.parse(body);
      const submitted = parsed.flag;
      if (!submitted) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing "flag" field. Send {"flag": "TARANTU{...}"}' }));
        return;
      }
      metrics.flag_attempts.push(submitted);
      const correct = submitted === flag;
      if (correct && !metrics.solved) {
        metrics.solved = true;
        metrics.time_to_solve_ms = Date.now() - metrics.startTime;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        correct,
        message: correct ? 'Correct! Flag accepted.' : 'Incorrect flag. Keep trying.',
      }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON. Send {"flag": "TARANTU{...}"}' }));
    }
  });
}

function startProxy(labPort, proxyPort, flag, metrics) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((clientReq, clientRes) => {
      const reqStart = Date.now();

      if (clientReq.method === 'POST' && clientReq.url === '/submit-flag') {
        handleFlagSubmission(clientReq, clientRes, flag, metrics);
        return;
      }

      const fwdHeaders = { ...clientReq.headers };
      fwdHeaders.host = `127.0.0.1:${labPort}`;

      const proxyReq = http.request({
        hostname: '127.0.0.1',
        port: labPort,
        path: clientReq.url,
        method: clientReq.method,
        headers: fwdHeaders,
      }, (proxyRes) => {
        const latency = Date.now() - reqStart;
        metrics.http_requests++;
        metrics.unique_paths.add(clientReq.url.split('?')[0]);
        metrics.http_log.push({
          ts: Date.now() - metrics.startTime,
          method: clientReq.method,
          path: clientReq.url,
          status: proxyRes.statusCode,
          latency_ms: latency,
        });

        const headers = Object.fromEntries(
          Object.entries(proxyRes.headers).map(([k, v]) => {
            if (k === 'location' && typeof v === 'string') {
              return [k, v
                .replace(`://127.0.0.1:${labPort}`, `://127.0.0.1:${proxyPort}`)
                .replace(`://localhost:${labPort}`, `://localhost:${proxyPort}`)];
            }
            return [k, v];
          })
        );

        clientRes.writeHead(proxyRes.statusCode, headers);
        proxyRes.pipe(clientRes);
      });

      proxyReq.on('error', (err) => {
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end(`Proxy error: ${err.message}`);
      });

      clientReq.pipe(proxyReq);
    });

    server.on('error', reject);
    server.listen(proxyPort, () => resolve(server));
  });
}

// ── Lab runner ─────────────────────────────────────────────────────

function serializeMetrics(metrics) {
  return {
    ...metrics,
    unique_paths: [...metrics.unique_paths],
    startTime: undefined,
  };
}

async function runLabCallback(row, opts, portOffset) {
  const labPort = opts.port + portOffset * 2;
  const proxyPort = labPort + 1;
  const metrics = createMetrics(row);
  const tag = `[${row.lab_id}]`.padEnd(50);

  process.stdout.write(`${tag} booting...`);
  let lab;
  try {
    lab = await bootLab(row, labPort);
  } catch (err) {
    console.log(` BOOT FAILED: ${err.message}`);
    metrics.error = `Boot failed: ${err.message}`;
    return serializeMetrics(metrics);
  }

  metrics.startTime = Date.now();
  const proxy = await startProxy(labPort, proxyPort, lab.flag, metrics);
  const baseUrl = `http://127.0.0.1:${proxyPort}`;
  console.log(` running on ${baseUrl}`);

  const cmd = opts.command.replace(/\{URL\}/g, baseUrl);
  const [shell, shellArg] = process.platform === 'win32'
    ? ['cmd.exe', '/c']
    : ['sh', '-c'];

  try {
    await new Promise((resolve, reject) => {
      const child = spawn(shell, [shellArg, cmd], {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: opts.timeout * 1000,
      });

      let stdout = '', stderr = '';
      child.stdout.on('data', d => { stdout += d; });
      child.stderr.on('data', d => { stderr += d; });

      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        setTimeout(() => { if (!child.killed) child.kill('SIGKILL'); }, 3000);
      }, opts.timeout * 1000);

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve(code);
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  } catch (err) {
    metrics.error = `Agent error: ${err.message}`;
  }

  metrics.wall_time_ms = Date.now() - metrics.startTime;
  proxy.close();
  killLab(lab.proc, lab.tmpDir);

  const status = metrics.solved ? '\x1b[32mSOLVED\x1b[0m' : '\x1b[31mFAILED\x1b[0m';
  console.log(`${tag} ${status}  (${metrics.http_requests} reqs, ${(metrics.wall_time_ms / 1000).toFixed(1)}s)`);

  return serializeMetrics(metrics);
}

async function runLabServer(row, opts, portOffset) {
  const labPort = opts.port + portOffset * 2;
  const proxyPort = labPort + 1;
  const metrics = createMetrics(row);

  console.log(`\n${'─'.repeat(70)}`);
  console.log(`  Lab: ${row.lab_id}`);
  console.log(`  ${row.title} (${row.difficulty})`);
  console.log(`${'─'.repeat(70)}`);

  process.stdout.write('  Booting...');
  let lab;
  try {
    lab = await bootLab(row, labPort);
  } catch (err) {
    console.log(` BOOT FAILED: ${err.message}`);
    metrics.error = `Boot failed: ${err.message}`;
    return serializeMetrics(metrics);
  }

  metrics.startTime = Date.now();
  const proxy = await startProxy(labPort, proxyPort, lab.flag, metrics);
  const baseUrl = `http://127.0.0.1:${proxyPort}`;

  console.log(` ready!`);
  console.log(`\n  Target:       ${baseUrl}`);
  console.log(`  Flag submit:  POST ${baseUrl}/submit-flag  {"flag": "TARANTU{...}"}`);
  console.log(`  Timeout:      ${opts.timeout}s`);
  console.log(`\n  Waiting for agent... (press Enter to skip this lab)\n`);

  const rl = readline.createInterface({ input: process.stdin });

  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      console.log('  Timeout reached.');
      resolve();
    }, opts.timeout * 1000);

    const checkSolved = setInterval(() => {
      if (metrics.solved) {
        clearTimeout(timer);
        clearInterval(checkSolved);
        console.log(`  Flag found after ${metrics.http_requests} requests!`);
        resolve();
      }
    }, 500);

    rl.once('line', () => {
      clearTimeout(timer);
      clearInterval(checkSolved);
      console.log('  Skipped.');
      resolve();
    });
  });

  rl.close();
  metrics.wall_time_ms = Date.now() - metrics.startTime;
  proxy.close();
  killLab(lab.proc, lab.tmpDir);

  const status = metrics.solved ? '\x1b[32mSOLVED\x1b[0m' : '\x1b[31mFAILED\x1b[0m';
  console.log(`  Result: ${status}  (${metrics.http_requests} reqs, ${(metrics.wall_time_ms / 1000).toFixed(1)}s)`);

  return serializeMetrics(metrics);
}

// ── Pool runner for callback mode ──────────────────────────────────

async function runPool(labs, opts) {
  const results = [];
  let nextIdx = 0;

  async function worker(workerId) {
    while (nextIdx < labs.length) {
      const idx = nextIdx++;
      const result = await runLabCallback(labs[idx], opts, workerId);
      results.push(result);
    }
  }

  const workers = [];
  const n = Math.min(opts.maxConcurrent, labs.length);
  for (let w = 0; w < n; w++) workers.push(worker(w));
  await Promise.all(workers);
  return results;
}

// ── Write results ──────────────────────────────────────────────────

function writeResults(results, outputDir) {
  fs.mkdirSync(outputDir, { recursive: true });

  for (const r of results) {
    const filepath = path.join(outputDir, `${r.lab_id}.json`);
    fs.writeFileSync(filepath, JSON.stringify(r, null, 2));
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const summaryPath = path.join(outputDir, `run_${timestamp}.json`);
  fs.writeFileSync(summaryPath, JSON.stringify(results, null, 2));

  return summaryPath;
}

// ── Summary ────────────────────────────────────────────────────────

function printSummary(results) {
  const solved = results.filter(r => r.solved);
  const failed = results.filter(r => !r.solved);

  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TARANTUBENCH EVALUATION SUMMARY');
  console.log(`${'═'.repeat(70)}\n`);

  for (const r of results) {
    const status = r.solved ? '\x1b[32m PASS \x1b[0m' : '\x1b[31m FAIL \x1b[0m';
    const reqs = `${r.http_requests} reqs`.padEnd(10);
    const time = `${(r.wall_time_ms / 1000).toFixed(1)}s`.padEnd(8);
    console.log(`  ${status} ${r.lab_id.padEnd(45)} ${reqs} ${time}`);
  }

  console.log(`\n  ${'─'.repeat(64)}`);
  console.log(`  Solve rate:   ${solved.length}/${results.length} (${((solved.length / results.length) * 100).toFixed(1)}%)`);

  const byDiff = {};
  for (const r of results) {
    const d = r.difficulty || 'Unknown';
    if (!byDiff[d]) byDiff[d] = { total: 0, solved: 0 };
    byDiff[d].total++;
    if (r.solved) byDiff[d].solved++;
  }
  console.log('\n  By difficulty:');
  for (const [d, s] of Object.entries(byDiff).sort()) {
    console.log(`    ${d.padEnd(15)} ${s.solved}/${s.total} (${((s.solved / s.total) * 100).toFixed(0)}%)`);
  }

  const byCat = {};
  for (const r of results) {
    const c = r.category || 'Unknown';
    if (!byCat[c]) byCat[c] = { total: 0, solved: 0 };
    byCat[c].total++;
    if (r.solved) byCat[c].solved++;
  }
  console.log('\n  By category:');
  for (const [c, s] of Object.entries(byCat).sort()) {
    console.log(`    ${c.padEnd(25)} ${s.solved}/${s.total} (${((s.solved / s.total) * 100).toFixed(0)}%)`);
  }

  if (solved.length > 0) {
    const avgReqs = (solved.reduce((s, r) => s + r.http_requests, 0) / solved.length).toFixed(1);
    const avgTime = (solved.reduce((s, r) => s + r.wall_time_ms, 0) / solved.length / 1000).toFixed(1);
    console.log(`\n  Solved avg:   ${avgReqs} reqs, ${avgTime}s`);
  }

  console.log('');
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();

  if (!opts.dataset) {
    console.error('Usage: node harness.js --dataset <path-to-jsonl> [--command <cmd>] [options]');
    console.error('\nModes:');
    console.error('  --command "python agent.py --url {URL}"   Callback mode (auto-run agent per lab)');
    console.error('  --mode server                             Server mode (print URL, wait for flag)');
    console.error('\nOptions:');
    console.error('  --timeout <seconds>       Per-lab timeout (default 300)');
    console.error('  --labs <id1,id2,...>       Only run specific labs');
    console.error('  --port <n>                Base port (default 4100)');
    console.error('  --max-concurrent <n>      Parallel labs in callback mode (default 1)');
    console.error('  --output <dir>            Results directory (default ./results)');
    process.exit(1);
  }

  let labs = loadDataset(opts.dataset);
  if (opts.labs) labs = labs.filter(r => opts.labs.includes(r.lab_id));

  if (labs.length === 0) {
    console.error('No labs matched. Check --dataset path and --labs filter.');
    process.exit(1);
  }

  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║            TARANTUBENCH EVALUATION HARNESS              ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`  Dataset:     ${opts.dataset}`);
  console.log(`  Labs:        ${labs.length}`);
  console.log(`  Mode:        ${opts.mode}`);
  console.log(`  Timeout:     ${opts.timeout}s per lab`);
  if (opts.command) console.log(`  Command:     ${opts.command}`);
  console.log(`  Output:      ${opts.output}`);
  console.log('');

  let results;

  if (opts.mode === 'callback' && opts.command) {
    results = await runPool(labs, opts);
  } else {
    results = [];
    for (let i = 0; i < labs.length; i++) {
      const r = await runLabServer(labs[i], opts, 0);
      results.push(r);
    }
  }

  const summaryPath = writeResults(results, opts.output);
  printSummary(results);
  console.log(`  Results written to: ${opts.output}`);
  console.log(`  Full run log:       ${summaryPath}\n`);
}

main().catch(err => {
  console.error('Harness error:', err);
  process.exit(1);
});
