import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

// @edition resolves to frontend/src/edition, or to the frontend/ directory of
// the private edition the backend build picks (scripts/edition.sh: the first
// ext/<name>/ with a go.mod; BOTMUX_EDITION=oss or =<name> overrides).
function editionModules(): string {
  const oss = path.resolve(__dirname, 'frontend/src/edition');
  const requested = process.env.BOTMUX_EDITION || '';
  if (requested === 'oss') return oss;
  const ext = path.resolve(__dirname, 'ext');
  const names = requested ? [requested] : fs.existsSync(ext) ? fs.readdirSync(ext).sort() : [];
  const edition = names.find((name) => fs.existsSync(path.join(ext, name, 'go.mod')));
  const dir = edition ? path.join(ext, edition, 'frontend') : '';
  return dir && fs.existsSync(dir) ? dir : oss;
}

// 前端独立目录 frontend/，构建产物输出到 dist/web（与服务端 serveIndex 的 WEB_DIR 对齐）。
// base：hash 资源的引用前缀。发布构建可用 CDN_BASE 指向静态资源 CDN（规避滚动发布时新旧 pod
// 互相取不到对方的 hash 资源导致白屏）；缺省 '/'（同源，由平台服务直接提供）。
export default defineConfig({
  root: 'frontend',
  base: process.env.CDN_BASE || '/',
  plugins: [react()],
  resolve: {
    alias: { '@edition': editionModules() },
  },
  build: {
    outDir: path.resolve(__dirname, 'dist/web'),
    emptyOutDir: true,
  },
});
