#!/usr/bin/env node
/**
 * 生成端到端演示工作区（D 盘本地目录）：
 *  1. 复制 fixtures/vibeshop 到 .demo/vibeshop —— 一个独立于本仓库的「用户项目」；
 *  2. git init + 基线提交（worktree 隔离与写回依赖 HEAD）；
 *  3. 制造一处未提交的本地改动（验证写回不破坏「正在开发的工作区」）。
 *
 * 用法: node scripts/seed-demo.mjs [demoDir]
 * 默认 demoDir: <仓库根>/.demo
 */
import { cpSync, rmSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = path.join(repoRoot, "fixtures", "vibeshop");
const demoDir = path.resolve(process.argv[2] ?? path.join(repoRoot, ".demo"));
const workspace = path.join(demoDir, "vibeshop");

function git(args, cwd) {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  }
  return r.stdout;
}

mkdirSync(demoDir, { recursive: true });
rmSync(workspace, { recursive: true, force: true });
cpSync(fixture, workspace, { recursive: true });

git(["init", "-q"], workspace);
git(["config", "user.email", "demo@guardbuild.local"], workspace);
git(["config", "user.name", "GuardBuild Demo"], workspace);
git(["config", "core.autocrlf", "false"], workspace);
git(["add", "-A"], workspace);
git(["commit", "-qm", "vibeshop 基线（含订单 IDOR 缺陷）"], workspace);

// 未提交的本地改动：追加到 src/app.js 末尾（远离补丁锚点区域，写回与回滚都应保留它）
const appJs = path.join(workspace, "src", "app.js");
const original = readFileSync(appJs, "utf8");
writeFileSync(
  appJs,
  `${original}\n// [本地未提交改动] 正在开发中的订单导出功能（写回修复后必须仍然保留）\n`
);

const status = git(["status", "--porcelain"], workspace).trim();
console.log(`[seed] 演示工作区: ${workspace}`);
console.log(`[seed] git status: ${status.replace(/\n/g, " | ")}`);
console.log("[seed] 完成：基线已提交，src/app.js 含一处未提交本地改动");
