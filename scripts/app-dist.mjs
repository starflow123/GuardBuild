#!/usr/bin/env node
/**
 * 分发构建：准备随包 Node → 生成带资源映射/签名的临时 Tauri 配置 → 构建 NSIS 安装器。
 *
 * 签名接口（全部走环境变量，不写仓库、不回显敏感值）：
 *   GUARDBUILD_SIGN_CERT_THUMBPRINT  证书 SHA1 指纹（signtool 自动选证书）
 *   GUARDBUILD_SIGN_TIMESTAMP_URL    时间戳服务，默认 http://timestamp.digicert.com
 *   GUARDBUILD_SIGN_DIGEST           摘要算法，默认 sha256
 *   GUARDBUILD_SIGN_COMMAND          自定义签名命令，必须包含 %1 占位符
 *
 * 未提供任何签名变量时产出未签名安装器，并在结尾明确提示。
 *
 * 用法:
 *   npm run app:dist
 *   GUARDBUILD_SIGN_CERT_THUMBPRINT=... npm run app:dist
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prepareRuntime } from "./prepare-runtime.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tauriDir = path.join(repoRoot, "src-tauri");
const overlayPath = path.join(tauriDir, ".tauri-dist.generated.json");

export const RESOURCE_MAP = {
  "runtime/": "runtime/",
  "../sidecar/main.mjs": "sidecar/main.mjs",
  "../sidecar/lib/": "sidecar/lib/",
  "../shared/": "shared/",
};

/** 只生成签名相关配置；未配置时返回空对象而不是假签名。 */
export function buildSigningConfig(env = process.env) {
  const win = {};
  const thumbprint = (env.GUARDBUILD_SIGN_CERT_THUMBPRINT ?? "").trim();
  const signCommand = (env.GUARDBUILD_SIGN_COMMAND ?? "").trim();
  if (thumbprint && signCommand) {
    throw new Error("GUARDBUILD_SIGN_CERT_THUMBPRINT 与 GUARDBUILD_SIGN_COMMAND 只能二选一");
  }
  if (thumbprint) {
    win.certificateThumbprint = thumbprint;
    win.digestAlgorithm = (env.GUARDBUILD_SIGN_DIGEST ?? "sha256").trim() || "sha256";
    win.timestampUrl = (env.GUARDBUILD_SIGN_TIMESTAMP_URL ?? "http://timestamp.digicert.com").trim();
  }
  if (signCommand) {
    if (!signCommand.includes("%1")) throw new Error("GUARDBUILD_SIGN_COMMAND 必须包含 %1 占位符");
    win.signCommand = signCommand;
  }
  return win;
}

export function buildDistOverlay(env = process.env) {
  const windows = buildSigningConfig(env);
  return {
    bundle: {
      active: true,
      targets: ["nsis"],
      resources: RESOURCE_MAP,
      windows: {
        ...windows,
        nsis: {
          installMode: "currentUser",
          languages: ["SimpChinese", "English"],
          displayLanguageSelector: true,
          compression: "lzma",
        },
      },
    },
  };
}

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: repoRoot, stdio: "inherit", env: process.env });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} 退出码 ${r.status}`);
}

export function findInstallers(dir = path.join(tauriDir, "target", "release", "bundle", "nsis")) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => n.toLowerCase().endsWith(".exe"))
    .map((n) => path.join(dir, n));
}

function main() {
  const info = prepareRuntime();
  console.log(`[dist] 随包 Node：${info.version}（${(info.size / 1024 / 1024).toFixed(1)} MB）`);

  const overlay = buildDistOverlay();
  const signed = Boolean(overlay.bundle.windows.certificateThumbprint || overlay.bundle.windows.signCommand);
  writeFileSync(overlayPath, `${JSON.stringify(overlay, null, 2)}\n`);
  console.log(`[dist] 安装器：NSIS（currentUser，中英双语）；签名：${signed ? "已配置" : "未配置（产出未签名安装器）"}`);

  try {
    run(process.execPath, [
      path.join(repoRoot, "node_modules", "@tauri-apps", "cli", "tauri.js"),
      "build",
      "--config",
      overlayPath,
    ]);
  } finally {
    rmSync(overlayPath, { force: true });
  }

  const installers = findInstallers();
  if (!installers.length) throw new Error("构建结束但未找到 NSIS 安装器（target/release/bundle/nsis/*.exe）");
  for (const p of installers) {
    console.log(`[dist] 产物：${p}（${(statSync(p).size / 1024 / 1024).toFixed(1)} MB）`);
  }
  if (!signed) {
    console.log("[dist] 提示：当前安装器未签名。用 GUARDBUILD_SIGN_CERT_THUMBPRINT 或 GUARDBUILD_SIGN_COMMAND 重新构建后再对外分发。");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`[dist] 失败：${e.message}`);
    process.exit(1);
  }
}
