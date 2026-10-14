# GuardBuild · 桌面安全 Agent

<p align="center">
  <img src="src-tauri/icons/128x128@2x.png" width="120" alt="GuardBuild" />
</p>

面向 Vibe Coding 开发者的本地安全 Agent：对正在开发的项目执行 **发现 → 复现 → 隔离修复 → 双重验收** 的完整取证工作流——把「感觉有漏洞」变成可复现的证据链，把「让 AI 改代码」变成经过验收的补丁。

- **只报告被真实打穿的漏洞**：每条发现附带真实请求证据与服务端决策归因，而非静态扫描的猜测（proof, not alerts）
- **修复先隔离后落地**：补丁在临时 git worktree 中生成并通过双重验收（攻击失效 + 业务不回归）；写回原工作区需用户授权，带备份、可回滚
- **CI 门禁模式**：无人工交互、按预声明策略授权、结构性禁止写回——只输出报告与已验证补丁

## 工作流原理

| # | 阶段 | 说明 |
| --- | --- | --- |
| 1 | 启动目标 | 按项目根 `guardbuild.json` 契约启动被检服务并就绪握手（缺省 `node server.js` + stdout `GB_LISTEN`） |
| 2 | 静态线索 | 分析路由与代码产出候选发现（如 IDOR 线索），只作为待实证的线索 |
| 3 | 动态实证 | 用「身份（普通用户/管理员/匿名）× 对象」用例矩阵真实请求服务：攻击用例证明越权可打穿，业务用例验证授权边界完好 |
| 4 | 决策关联 | 目标提供 `/__diag/decisions` 诊断端点时，将每次越权请求归因到具体服务端决策点 |
| 5 | 隔离修复 | 在临时 git worktree 中生成修复补丁，不触碰原工作区 |
| 6 | 双重验收 | 修复后：攻击用例必须全部不再复现，且业务用例必须全部保持通过 |
| 7 | 产物 | `report.json` / `report.md` 报告 + SQLite 证据链（7 张表）；桌面模式可经用户授权写回原工作区 |

## 架构与信任模型

```
┌──────────────────────────────┐
│ React UI（Tauri WebView）     │  工作流界面：进度 / 证据 / Diff 审阅 / 授权
└───────────────┬──────────────┘
                │ Tauri invoke / event
┌───────────────┴──────────────┐
│ Rust Host（守门人）           │  唯一的系统能力持有者：
│  · token.rs 作用域令牌        │  文件 / 进程 / 网络 / git 全部经令牌放行；
│  · gitops 工作树·写回·回滚    │  令牌绑定路径、端口、补丁哈希，用完即撤
│  · vault 密钥保管 + 日志脱敏  │
└───────────────┬──────────────┘
                │ JSON-RPC 2.0 over stdio（NDJSON，双向）
┌───────────────┴──────────────┐
│ Node.js Sidecar（编排器）     │  零系统权限、零 npm 依赖（node:sqlite）：
│  analyzer → planner →         │  一切系统动作只能「申请令牌 → 由 Host 执行」
│  probe → patcher → report     │
└──────────────────────────────┘
```

**信任模型**：Sidecar 不可信但可审计——它编排全部工作流，却无法绕过 Host 直接触碰系统。`workspace.write` / `workspace.rollback` 永远不能由 Sidecar 申请，只能由用户在 UI 批准 Diff / 触发回滚后，由 Host 直接签发绑定补丁哈希（或备份 ID）的令牌。

## 快速开始

前提：Node.js ≥ 22.5（依赖 `node:sqlite`）、Rust stable。无头 / CI 路径不需要 GUI 系统依赖（Linux 上无需 WebKit）；桌面模式需要 Tauri 2 的平台依赖。

```bash
# 桌面应用（开发 / 构建）
npm install
npm run app:dev        # 开发模式（Vite + Tauri）
npm run app:build      # 构建（--no-bundle）

# 无头验收（零 npm 依赖：构建宿主后即可运行）
npm run host:headless  # 构建无头宿主（--no-default-features）
npm run e2e            # 主工作流 E2E（31 断言，自动生成 .demo 演示目标）
npm run e2e:gate       # CI gate 演练（27 断言，4 轮裁决 + 报告产物）
npm run seed-demo      # 单独生成演示工作区 .demo/vibeshop（供桌面端手动演练）

# 单元测试
npm run test:sidecar   # Sidecar（node --test）
npm run test:rust      # Rust Host
```

## guardbuild.json（目标启动契约）

在被检项目根放置 `guardbuild.json` 声明启动方式、测试身份与预声明作用域；文件缺失或字段非法时逐项回落到缺省值：

```json
{
  "start": {
    "cmd": "node",
    "args": ["server.js"],
    "env": { "PORT": "0" },
    "readyPattern": "GB_LISTEN",
    "readyTimeoutMs": 20000
  },
  "identities": [
    { "name": "alice", "username": "alice", "password": "alice123", "role": "user" },
    { "name": "admin", "username": "admin", "password": "admin123", "role": "admin" }
  ],
  "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe"]
}
```

- `start.env.PORT=0`：让服务自选端口；就绪以 `readyPattern` 在 stdout 出现为准
- `identities`：至少 2 个，否则回退到内置演示身份；`role: "admin"` 的身份用于管理端用例
- `scopes`：仅 CI gate 模式读取，作为「预声明授权」白名单；桌面模式不生效（仍逐次征求用户授权）

## CI 门禁接入（GitHub Actions）

```yaml
- name: GuardBuild Gate
  uses: <owner>/<repo>@main   # 替换为实际仓库地址；建议固定到 tag 或 commit
  with:
    project: .                # 目标项目路径（可含 guardbuild.json）
    report-dir: guardbuild-report
    # data-dir: guardbuild-evidence
```

退出码可直接决定 job 成败：

| 退出码 | verdict | 含义 |
| --- | --- | --- |
| 0 | `no_candidates` / `not_reproducible` | 无漏洞证据 |
| 1 | `vulnerable`（附已验证补丁） | 漏洞证据成立：`patchStatus: verified`（通过双重验收）或 `verify_failed`（修复未通过验收，附证据） |
| 2 | `failed` / `aborted` / `timeout` | 执行失败（契约 / 环境 / 内部错误 / 超时 / 中断） |

- 输出：`verdict`、`exit-code`、`patch-hash`；报告目录含 `report.json`、`report.md`、`gate.json`（GB_GATE 裁决行）、`gate.log`
- gate 语义：无人工交互；作用域仅按 `guardbuild.json.scopes` 预声明签发（审批留痕 `via: gate-policy`）；`workspace.write` 被结构性禁止，**不修改被测工作区**，只输出已验证补丁供人工应用

## 安全模型

- **作用域令牌**：`project.read`（限定根目录）/ `worktree.write`（仅临时工作树）/ `proc.spawn`（可执行与参数白名单）/ `net.probe`（仅回环）/ `workspace.write`（绑定补丁哈希，仅 UI 批准后签发）/ `workspace.rollback`（绑定备份 ID，仅 UI 触发）
- **写回保护**：写回前自动备份原文件；回滚按备份恢复，冲突文件不覆盖；gate 模式在 Host 层直接拒绝写回
- **凭证保护**：目标身份凭证直接存入 Host 保险库，不流经 Sidecar；日志全量脱敏
- **全程留痕**：授权与审批写入 SQLite（`approvals.via` 区分 `user-consent` / `auto-consent` / `policy` / `gate-policy`）

## 仓库结构

```
├─ src/                    React 前端（工作流界面）
├─ src-tauri/              Tauri 壳 + Rust Host
│  ├─ src/core/            令牌 / 文件 / git / 进程 / 网络能力与守门逻辑
│  ├─ src/bin/headless.rs  无头宿主（E2E 演练 + CI gate）
│  └─ icons/               应用图标
├─ sidecar/                Node 编排器（零依赖）
│  ├─ lib/                 analyzer / planner / probe / patcher / report / statemachine …
│  └─ tests/               单元测试
├─ shared/protocol.mjs     协议唯一事实来源（双向 RPC 方法名与常量）
├─ scripts/                seed-demo / e2e-headless / e2e-gate
├─ fixtures/vibeshop/      内置演示目标（含订单 IDOR 缺陷）
├─ action.yml              GitHub Action（composite）
└─ .github/workflows/      自测矩阵（ubuntu-latest + windows-latest）
```

## 已知边界

- 动态用例当前聚焦 Node.js HTTP/JSON 服务形态；其它技术栈需要自定义启动契约与用例（尚未泛化）
- Windows 全链路已实测；Linux / macOS 构建与运行尚未在真实环境验证（CI 矩阵已配置，待首次运行）
- GitHub Action 已按 runner 脚本逐字本地模拟，尚未在真实 runner 上运行
- 尚未在第三方真实开源项目上 dogfood

## 开发备注

- 无头宿主构建使用 `--no-default-features`（绕过 `gui` feature，Linux 上无需 WebKit 依赖）
- 演练脚本自动解析宿主二进制：`GUARDBUILD_HEADLESS_BIN` > `target/debug` > `target/release`
- gate 超时缺省 15 分钟，可用 `GUARDBUILD_GATE_TIMEOUT_MS` 覆盖

## License

尚未选择开源许可证。在添加 LICENSE 之前，默认保留所有权利。
