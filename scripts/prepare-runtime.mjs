#!/usr/bin/env node
/**
 * 准备随包 Node 运行时：把当前 node 可执行文件复制到 src-tauri/runtime/。
 *
 * 分发要求：安装目录里同时存在 runtime/node(.exe)、sidecar/、shared/；
 * Host 会优先使用随包 node（见 src-tauri/src/core/runtime.rs），找不到才回落 PATH。
 *
 * 用法:
 *   node scripts/prepare-runtime.mjs                 # 复制当前 node
 *   GUARDBUILD_NODE_SOURCE=/path/to/node node scripts/prepare-runtime.mjs
 */
import { copyFileSync, existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const MIN_NODE = [22, 5, 0];

export function parseNodeVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(v).trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function isSupportedNode(version) {
  const p = parseNodeVersion(version);
  if (!p) return false;
  for (let i = 0; i < MIN_NODE.length; i++) {
    if (p[i] > MIN_NODE[i]) return true;
    if (p[i] < MIN_NODE[i]) return false;
  }
  return true;
}

export function nodeFileName(platform = process.platform) {
  return platform === "win32" ? "node.exe" : "node";
}

const NODE_LICENSE = `Node.js is licensed for use as follows:

Copyright Node.js contributors. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Node.js also bundles third-party libraries (OpenSSL, V8, libuv, etc.);
their full license texts ship with the official Node.js distribution at
https://nodejs.org/en/about/previous-releases
`;

/** 复制运行时并返回安装目录中的路径；失败时抛错而不是静默跳过。 */
export function prepareRuntime({ source, destRoot = path.join(repoRoot, "src-tauri"), platform = process.platform, version = process.versions.node } = {}) {
  const src = source ?? process.execPath;
  if (!src || !existsSync(src)) throw new Error(`找不到 Node 运行时源文件：${src}`);
  if (!isSupportedNode(version)) throw new Error(`Node ${version} 低于最低要求 ${MIN_NODE.join(".")}（node:sqlite 需要）`);

  const runtimeDir = path.join(destRoot, "runtime");
  mkdirSync(runtimeDir, { recursive: true });
  const dest = path.join(runtimeDir, nodeFileName(platform));
  copyFileSync(src, dest);
  if (!statSync(dest).size) throw new Error(`复制后的运行时为空：${dest}`);

  writeFileSync(path.join(runtimeDir, "VERSION"), `v${version}\n`);
  writeFileSync(path.join(runtimeDir, "THIRD-PARTY-NOTICES.txt"), NODE_LICENSE);

  for (const rel of [path.join("sidecar", "main.mjs"), path.join("shared", "protocol.mjs")]) {
    if (!existsSync(path.join(repoRoot, rel))) throw new Error(`缺少随包资源：${rel}`);
  }
  return { nodePath: dest, version: `v${version}`, size: statSync(dest).size };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const info = prepareRuntime({ source: process.env.GUARDBUILD_NODE_SOURCE });
  console.log(`随包 Node 已准备：${info.nodePath}（${info.version}，${(info.size / 1024 / 1024).toFixed(1)} MB）`);
}
