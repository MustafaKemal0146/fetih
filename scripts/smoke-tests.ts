import { existsSync } from 'fs';
import { resolve } from 'path';

const root = process.cwd();
const requiredFiles = [
  'dist/cli.js',
  'dist/version.js',
  'dist/prompts/system.js',
  'FETIH-Apps/Core/FETIH_Engine.py',
];

let failed = false;

for (const rel of requiredFiles) {
  const abs = resolve(root, rel);
  if (!existsSync(abs)) {
    console.error(`❌ Eksik dosya: ${rel}`);
    failed = true;
  } else {
    console.log(`✅ ${rel}`);
  }
}

if (failed) {
  process.exitCode = 1;
} else {
  console.log('✅ Smoke test başarılı.');
}
