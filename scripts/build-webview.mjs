import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import { join } from 'node:path';

const out = join('src-tauri', 'dist');
await mkdir(out, { recursive: true });
await Promise.all([
  copyFile('webview/index.html', join(out, 'index.html')),
  copyFile('webview/app.css', join(out, 'app.css')),
]);
await build({
  entryPoints: ['webview/pages/app.ts'],
  bundle: true,
  target: 'es2022',
  format: 'iife',
  platform: 'browser',
  outfile: join(out, 'app.js'),
});
console.log('WebView assets built into ' + out);
