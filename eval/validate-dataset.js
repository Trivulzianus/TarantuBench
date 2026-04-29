#!/usr/bin/env node
/**
 * Validate a TarantuBench JSONL dataset before running evaluations.
 */

import fs from 'node:fs';
import path from 'node:path';

const REQUIRED_FIELDS = [
  'lab_id',
  'title',
  'description',
  'objectives',
  'hints',
  'difficulty',
  'category',
  'vuln_subtype',
  'chain_type',
  'server_code',
  'dependencies',
];

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    dataset: null,
    hf: null,
    revision: 'main',
    filename: 'tarantubench-v1.jsonl',
    expectedCount: null,
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dataset' && args[i + 1]) opts.dataset = args[++i];
    if (args[i] === '--hf' && args[i + 1]) opts.hf = args[++i];
    if (args[i] === '--revision' && args[i + 1]) opts.revision = args[++i];
    if (args[i] === '--filename' && args[i + 1]) opts.filename = args[++i];
    if (args[i] === '--expected-count' && args[i + 1]) {
      opts.expectedCount = Number.parseInt(args[++i], 10);
    }
  }

  return opts;
}

function usage() {
  console.error('Usage: node validate-dataset.js (--dataset <path> | --hf <org/name>) [options]');
  console.error('');
  console.error('Options:');
  console.error('  --expected-count <n>  Expected number of JSONL rows');
  console.error('  --revision <rev>      Hugging Face revision/commit (default: main)');
  console.error('  --filename <name>     Dataset JSONL filename (default: tarantubench-v1.jsonl)');
}

async function readDataset(opts) {
  if (opts.dataset) {
    return {
      source: path.resolve(opts.dataset),
      text: fs.readFileSync(opts.dataset, 'utf-8'),
    };
  }

  if (opts.hf) {
    const url = `https://huggingface.co/datasets/${opts.hf}/resolve/${opts.revision}/${opts.filename}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
    }
    return { source: url, text: await response.text() };
  }

  usage();
  process.exit(1);
}

function parseJsonl(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
  return lines.map((line, idx) => {
    try {
      return JSON.parse(line);
    } catch (err) {
      throw new Error(`Invalid JSON on line ${idx + 1}: ${err.message}`);
    }
  });
}

function validateRows(rows, expectedCount) {
  const errors = [];
  const seenIds = new Set();

  if (expectedCount !== null && rows.length !== expectedCount) {
    errors.push(`Expected ${expectedCount} rows, found ${rows.length}`);
  }

  rows.forEach((row, idx) => {
    const prefix = `row ${idx + 1}${row.lab_id ? ` (${row.lab_id})` : ''}`;

    for (const field of REQUIRED_FIELDS) {
      if (!(field in row)) errors.push(`${prefix}: missing required field "${field}"`);
    }

    if (typeof row.lab_id !== 'string' || row.lab_id.length === 0) {
      errors.push(`${prefix}: lab_id must be a non-empty string`);
    } else if (seenIds.has(row.lab_id)) {
      errors.push(`${prefix}: duplicate lab_id "${row.lab_id}"`);
    } else {
      seenIds.add(row.lab_id);
    }

    if (!Array.isArray(row.objectives)) errors.push(`${prefix}: objectives must be an array`);
    if (!Array.isArray(row.hints)) errors.push(`${prefix}: hints must be an array`);
    if (typeof row.server_code !== 'string' || !row.server_code.includes('app.listen')) {
      errors.push(`${prefix}: server_code must include an Express app.listen call`);
    }
    if (typeof row.dependencies !== 'object' || row.dependencies === null || Array.isArray(row.dependencies)) {
      errors.push(`${prefix}: dependencies must be an object`);
    }
  });

  return errors;
}

async function main() {
  const opts = parseArgs();
  const { source, text } = await readDataset(opts);
  const rows = parseJsonl(text);
  const errors = validateRows(rows, opts.expectedCount);

  console.log(`Source: ${source}`);
  console.log(`Rows:   ${rows.length}`);

  if (errors.length > 0) {
    console.error('\nDataset validation failed:');
    for (const err of errors) console.error(`- ${err}`);
    process.exit(1);
  }

  console.log('Schema: OK');
}

main().catch(err => {
  console.error(`Dataset validation error: ${err.message}`);
  process.exit(1);
});
