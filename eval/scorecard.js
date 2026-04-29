#!/usr/bin/env node
/**
 * TarantuBench Scorecard Generator
 *
 * Reads per-lab JSON reports from the results directory and produces
 * an aggregate scorecard in both JSON and Markdown formats.
 *
 * Usage:
 *   node scorecard.js [--results <dir>] [--output <path>]
 *
 * Options:
 *   --results <dir>   Results directory (default ./results)
 *   --output <path>   Output base name without extension (default ./scorecard)
 *                     Writes <path>.json and <path>.md
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    results: path.join(__dirname, 'results'),
    output: path.join(__dirname, 'scorecard'),
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--results' && args[i + 1]) opts.results = args[++i];
    if (args[i] === '--output' && args[i + 1]) opts.output = args[++i];
  }
  return opts;
}

function loadResults(dir) {
  if (!fs.existsSync(dir)) {
    console.error(`Results directory not found: ${dir}`);
    process.exit(1);
  }

  const files = fs.readdirSync(dir).filter(f =>
    f.endsWith('.json') && !f.startsWith('run_') && !f.startsWith('scorecard')
  ).sort();

  if (files.length === 0) {
    console.error('No per-lab result files found. Run the harness first.');
    process.exit(1);
  }

  return files
    .map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8')))
    .sort((a, b) => String(a.lab_id).localeCompare(String(b.lab_id)));
}

function groupBy(results, key) {
  const groups = {};
  for (const r of results) {
    const k = r[key] || 'unknown';
    if (!groups[k]) groups[k] = { total: 0, solved: 0, results: [] };
    groups[k].total++;
    if (r.solved) groups[k].solved++;
    groups[k].results.push(r);
  }
  return groups;
}

function buildScorecard(results) {
  const solved = results.filter(r => r.solved);
  const failed = results.filter(r => !r.solved);

  const byDifficulty = groupBy(results, 'difficulty');
  const byCategory = groupBy(results, 'category');
  const byChain = {
    'single-vuln': { total: 0, solved: 0 },
    'multi-chain': { total: 0, solved: 0 },
  };
  for (const r of results) {
    const key = r.chain_type ? 'multi-chain' : 'single-vuln';
    byChain[key].total++;
    if (r.solved) byChain[key].solved++;
  }

  const solvedStats = solved.length > 0 ? {
    avg_http_requests: +(solved.reduce((s, r) => s + r.http_requests, 0) / solved.length).toFixed(1),
    avg_wall_time_s: +(solved.reduce((s, r) => s + r.wall_time_ms, 0) / solved.length / 1000).toFixed(1),
    avg_flag_attempts: +(solved.reduce((s, r) => s + r.flag_attempts.length, 0) / solved.length).toFixed(1),
  } : null;

  return {
    summary: {
      total_labs: results.length,
      solved: solved.length,
      failed: failed.length,
      solve_rate: +((solved.length / results.length) * 100).toFixed(1),
    },
    by_difficulty: Object.fromEntries(
      Object.entries(byDifficulty).sort().map(([k, v]) => [k, {
        total: v.total,
        solved: v.solved,
        solve_rate: +((v.solved / v.total) * 100).toFixed(1),
      }])
    ),
    by_category: Object.fromEntries(
      Object.entries(byCategory).sort().map(([k, v]) => [k, {
        total: v.total,
        solved: v.solved,
        solve_rate: +((v.solved / v.total) * 100).toFixed(1),
      }])
    ),
    by_chain: Object.fromEntries(
      Object.entries(byChain).map(([k, v]) => [k, {
        total: v.total,
        solved: v.solved,
        solve_rate: v.total > 0 ? +((v.solved / v.total) * 100).toFixed(1) : 0,
      }])
    ),
    solved_stats: solvedStats,
    per_lab: results.map(r => ({
      lab_id: r.lab_id,
      difficulty: r.difficulty,
      category: r.category,
      chain_type: r.chain_type || null,
      solved: r.solved,
      http_requests: r.http_requests,
      wall_time_ms: r.wall_time_ms,
      flag_attempts: r.flag_attempts.length,
      unique_paths: (r.unique_paths || []).length,
    })),
  };
}

function renderMarkdown(sc) {
  const lines = [];
  const pct = (n, d) => d > 0 ? `${((n / d) * 100).toFixed(1)}%` : '—';

  lines.push('# TarantuBench Scorecard');
  lines.push('');
  lines.push(`**Solve rate: ${sc.summary.solved}/${sc.summary.total_labs} (${sc.summary.solve_rate}%)**`);
  lines.push('');

  lines.push('## Per-Lab Results');
  lines.push('');
  lines.push('| Lab | Difficulty | Category | Result | Requests | Time |');
  lines.push('|-----|-----------|----------|--------|----------|------|');
  for (const r of sc.per_lab) {
    const status = r.solved ? 'PASS' : 'FAIL';
    const time = `${(r.wall_time_ms / 1000).toFixed(1)}s`;
    lines.push(`| ${r.lab_id} | ${r.difficulty} | ${r.category} | ${status} | ${r.http_requests} | ${time} |`);
  }
  lines.push('');

  lines.push('## By Difficulty');
  lines.push('');
  lines.push('| Difficulty | Solved | Total | Rate |');
  lines.push('|-----------|--------|-------|------|');
  for (const [d, s] of Object.entries(sc.by_difficulty)) {
    lines.push(`| ${d} | ${s.solved} | ${s.total} | ${s.solve_rate}% |`);
  }
  lines.push('');

  lines.push('## By Category');
  lines.push('');
  lines.push('| Category | Solved | Total | Rate |');
  lines.push('|----------|--------|-------|------|');
  for (const [c, s] of Object.entries(sc.by_category)) {
    lines.push(`| ${c} | ${s.solved} | ${s.total} | ${s.solve_rate}% |`);
  }
  lines.push('');

  lines.push('## Single-Vuln vs Multi-Chain');
  lines.push('');
  lines.push('| Type | Solved | Total | Rate |');
  lines.push('|------|--------|-------|------|');
  for (const [t, s] of Object.entries(sc.by_chain)) {
    lines.push(`| ${t} | ${s.solved} | ${s.total} | ${s.solve_rate}% |`);
  }
  lines.push('');

  if (sc.solved_stats) {
    lines.push('## Solved Lab Averages');
    lines.push('');
    lines.push(`- **Avg HTTP requests:** ${sc.solved_stats.avg_http_requests}`);
    lines.push(`- **Avg wall time:** ${sc.solved_stats.avg_wall_time_s}s`);
    lines.push(`- **Avg flag attempts:** ${sc.solved_stats.avg_flag_attempts}`);
    lines.push('');
  }

  return lines.join('\n');
}

function main() {
  const opts = parseArgs();
  const results = loadResults(opts.results);

  console.log(`Loaded ${results.length} lab results from ${opts.results}`);

  const scorecard = buildScorecard(results);

  const jsonPath = opts.output + '.json';
  fs.writeFileSync(jsonPath, JSON.stringify(scorecard, null, 2));
  console.log(`  JSON:     ${jsonPath}`);

  const mdPath = opts.output + '.md';
  fs.writeFileSync(mdPath, renderMarkdown(scorecard));
  console.log(`  Markdown: ${mdPath}`);

  console.log(`\nSolve rate: ${scorecard.summary.solved}/${scorecard.summary.total_labs} (${scorecard.summary.solve_rate}%)`);
}

main();
