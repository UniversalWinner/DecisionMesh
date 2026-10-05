#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { getEventSchemaText } from '../index.js';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === 'event') {
  process.stdout.write(getEventSchemaText());
} else if (args.length === 1 && args[0] === '--version') {
  const metadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  process.stdout.write(metadata.version + '\n');
} else if (args.length === 0 || (args.length === 1 && args[0] === '--help')) {
  process.stdout.write('Usage: decisionmesh-schema event | --version | --help\nExports a structural schema; does not run the Decision Mesh application.\n');
} else {
  process.stderr.write('Unsupported arguments. Use decisionmesh-schema --help.\n');
  process.exitCode = 2;
}
