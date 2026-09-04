#!/usr/bin/env node
import { run } from '../src/cli.js';

run(process.argv.slice(2)).then((exitCode) => {
  process.exitCode = exitCode;
}).catch((error) => {
  console.error(`trace2fix: ${error.message}`);
  process.exitCode = 1;
});
