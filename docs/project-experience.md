# GuardBuild · 项目经历

> 用途：简历 / 面试用项目经历。分三档：一句话版、简历条目版、面试展开版。
> 数据基准日：2026-10-24，均对照仓库当前代码与产物核实过（见文末「可核验出处」）。
> 对外统一口径见 `docs/support-matrix.md`；本文与它冲突时以支持矩阵与仓库代码为准。

---

## 一句话版

独立设计并实现 GuardBuild——一个「发现 → 沙箱复现 → 隔离修复 → 双重验收」的本地安全 Agent（Tauri + Rust 权限宿主 + 零依赖 Node 编排器，约 4.7 万行含测试），把大模型参与的自动修复变成有真实攻击证据与回归验证背书的产品能力，而非又一个扫描告警列表。

---

## 简历条目版（可直接粘贴）

**GuardBuild · 面向 Vibe Coding 开发者的本地安全 Agent**（独立开发，2026）
技术栈：Tauri 2 / Rust / React + TypeScript / Node.js 22（`node:sqlite`）/ JSON-RPC 2.0 / GitHub Actions

- 设计「最小权限宿主」架构：Rust Host 是唯一系统能力持有者，7 类作用域令牌（`project.read` / `worktree.write` / `proc.spawn` / `net.probe` / `net.egress` / `workspace.write` / `workspace.rollback`）绑定路径、端口与补丁哈希；不可信的 Node 编排器只能通过「申请令牌 → 由 Host 执行」动作，无法绕过边界。Sidecar **零 npm 依赖**，凭证进 Host 保险库、日志全量脱敏。
- 提出并实现 **proof, not alerts** 取证工作流：静态分析只产线索，必须用「身份 × 对象」用例矩阵在沙箱内真实打穿才计为漏洞；每条发现附可复现 curl PoC 与 SQLite 证据链（7 张表），授权诊断端点可把攻击归因到服务端决策点。
- 覆盖 **10 类可复现漏洞**（对象级越权（含查询参数形态）/ 无鉴权读取与纵向越权 / 路径穿越 / SQL 注入 / 命令注入 / SSRF / 文件上传 / JWT 伪造令牌 / 业务逻辑跳步与并发双花 / Supabase RLS 与 service_role 暴露）与 **7 套框架适配器**（Express、Next.js、NestJS、tRPC、GraphQL、Supabase/PostgREST、FastAPI/Flask/Django-DRF），并识别 10+ 种取数形态（Prisma、Drizzle、Knex、裸 SQL）。
- 打通**自动修复闭环**：补丁只在临时 git worktree 生成，双重验收（攻击用例全阻断 + 业务用例零回归）通过才进 `writeback_pending`，用户审阅 Diff 后授权写回，带备份与冲突安全回滚；CI gate 模式结构性禁止写回、单轮不重试，保证输出可复现。
- 引入 **LLM 三通道且严格限制其裁决权**：接入侦察（未知框架推断启动/登录/路由）、编码代理（5 类候选的补丁意图，可先 `read`/`list` 只读自查，S2-full 允许按依赖闭包跨文件改 4 个已有文件与新建 3 个文件）、有界启动代理（S3-full，本地交互模式按候选启动契约实跑验证，gate/CI 结构性禁用）。模型输出经结构白名单、锚点逐字命中、写集边界、禁用文件与危险调用扫描逐条校验；LLM 不判定漏洞、不生成身份、不参与验收；修复失败按 `fixRounds`（默认 2、上限 5）回灌证据有界重试，仍失败则回落 `vulnerable_unfixed`。
- 建 **精度基准**（12 个标注靶场语料）量化漏报/误报/退出码一致率：当前基线动态召回 23/23、误报 0/23、退出码一致 12/12、静态召回 23/23、零模型调用；含干净对照组靶场验证「动态澄清静态误报」。
- 工程化交付：纯黑盒外部扫描模式（URL 即可、OpenAPI 发现 + 路由爆破 + 前端 JS 提取、写操作默认关）、受限 `docker run` 容器沙箱、GitHub Action 门禁（三档退出码语义）、无头宿主（Linux 无需 WebKit 依赖）、独立 exe 单文件产物；测试含 29 个 Sidecar 单测文件（357 项）+ 42 个 Rust 测试 + 21 套端到端演练脚本。
- 以真实项目反向驱动迭代：在 OWASP Juice Shop v20.3.0 跑通全链路（静态分析 → email 登录 → 越权复现 → 隔离修复 → 双重验收 verified），据此定位并修复 10 项真实接入失败点（端口争用、就绪行解析、CRLF、挂载级鉴权误判、非 git 仓库预检等）；另在 DVWA / DVNA 等公开靶场与多个用户真实项目上实测。

---

## 面试展开版

### 项目背景与我要解决的问题

AI 辅助编程普及后，「能跑但没人审过」的代码直接进生产。现有 SAST 工具的问题是**告警多、误报高、且没人知道这条告警在真实运行时到底能不能打穿**；而「让 AI 直接改代码」的问题是**改完没人验证，改坏了也不知道**。

GuardBuild 的定位夹在中间：把漏洞从「静态猜测」变成「沙箱里真实打穿的证据」，再把修复从「AI 说了算」变成「隔离补丁 + 攻击失效 + 业务不回归」的验收结果。

### 三个我认为是这个项目的核心设计决策

**1. 不可信编排器 + 能力守门人**
把编排逻辑（Node Sidecar）当成不可信第三方来设计：它不持有任何系统能力，所有文件/进程/网络/git 动作必须申请令牌，由 Rust Host 执行并留痕。写回原工作区这条能力 Sidecar **根本无法申请**，只能由用户在 UI 批准后 Host 直接签发绑定补丁哈希的令牌。
带来的收益：LLM 输出不可预测也不需要预测——它的补丁意图会被逐条校验（锚点必须逐字唯一命中、禁改测试与配置与锁文件、新增内容含 `eval`/`child_process` 即拒），越界的直接丢弃，不污染其余补丁。

**2. 双重验收作为唯一的放行依据**
`verified` 的定义是：攻击用例全部不再复现 **且** 业务用例全部保持通过。前者防「没修好」，后者防「修坏了」。裁决只看实测证据，模型不参与。这条纪律使得即使 LLM 完全胡说，最坏结果也只是产出一个被驳回的意图，而不是一条假的「已修复」。

**3. 精度基准而不是单点 demo**
12 个标注靶场语料 + 逐靶场的期望复现用例集合，指标是动态召回率、误报率、退出码一致率，任一漏报/误报即基准失败。含一个「干净对照」靶场（归属校验封装在辅助函数里，静态看像漏、运行期真实拒绝），专门用来证明「动态能澄清静态误报」而不是只会喊狼来了。

### 难点（真正花时间的地方）

- **让任意真实项目跑起来**：这是全链路第一道坎，也是失败率最高的地方。做了启动契约自动探测（Procfile / package.json scripts / Python 入口 / 子目录 monorepo）、`${GB_PORT}` 空闲端口槽位（解决服务硬编码端口导致的双实例冲突）、就绪行端口解析（剥 ANSI、行内 JSON、`host:port`、「端口 NNNN」中文形状）、服务无输出时回环 HTTP 探活兜底，以及 13 类启动失败诊断码给出可操作建议。
- **动态复现的判据设计**：命令注入不能用「输入被反射」当证据（大量误报），改成 shell 展开令牌回显；SQL 注入要列表行数变化或数据库报错特征双证据之一；无法确证记 `inconclusive`，不算漏洞。宁可不报也不假报。
- **Windows 全链路**：`.cmd` shim 沿 PATH×PATHEXT 解析、CRLF 锚点匹配、进程树清理、junction 与 worktree 删除互相穿透的坑。

### 我知道它现在不强的地方（诚实边界）

- 语言栈只覆盖 js/ts/python/graphql，**Java/Spring 是双硬边界**（无静态适配器 + 启动器白名单没有 java/mvn/gradle），Spring 项目接入必然空候选。
- 确定性模板补丁只覆盖有明确归属校验插入位的形态（Express/手写路由）；其余形态靠编码代理尝试，补不动就 `vulnerable_unfixed` 交人工。
- 编码代理已从「单文件、无工具」推进到 S2-full：可 `read`/`list` 隔离 worktree 做只读自查，可按依赖闭包跨文件改 4 个已有文件、新建 3 个文件；失败会回灌用例、修复后实例日志尾部与上一轮 diff。但写集之外仍一律拒绝，补丁仍只在隔离 worktree 生成。
- S3-full 启动代理只在**本地交互模式**启用（gate/CI 结构性禁用），且 Docker 沙箱只是运行时隔离（项目目录读写挂载），不构成对恶意仓库的安全边界——所以它解决的是「接入未知项目」，不是「安全运行不可信代码」。
- CI 三平台自测矩阵已全绿（2026-10-24，run `40061875847` / 提交 `ed1e793`，含分发布局 E2E；更早 run `40060626570` / `edf4214`、`40057156477` / `cdd4876` 同样全绿）；这只证明自测矩阵本身通过，不代表任意项目接入都能跑通。
- 广度仍是刻意取舍：安全头缺失、依赖 CVE、OAuth 流程、多步业务链不在覆盖内；XSS / CSRF / CORS 只做到黑盒动态取证（反射型 canary、Cookie 会话跨站表单、CORS 反射 Origin + 允许凭证），没有静态线索与自动补丁；无源码时 SSRF / 上传 / JWT / 业务逻辑与竞态也不会被探测。

---

## 可核验出处

| 说法 | 出处 |
| --- | --- |
| 4.7 万行量级 | `sidecar`（含测试）29,474 行、`src-tauri/src` 6,046、`src` 3,144、`scripts` 8,238、`shared/protocol.mjs` 216 |
| 7 类作用域令牌 | `README.md` 「安全模型」、`src-tauri/src/core/token.rs` |
| Host 结构性禁止 gate 写回 | `src-tauri/src/core/host.rs:1815 approve_writeback`（要求 `writeback_pending` + 补丁哈希匹配） |
| 跨文件补丁边界 | `sidecar/lib/llm-patcher.mjs:491`（候选外最多 4 个已有文件 + 新建 3 个）；`llm-patcher.mjs:494 crossFilePatchEnabled` gate 下禁用 |
| 5 类 LLM 可修候选 | `sidecar/lib/patcher.mjs:21 LLM_KINDS` |
| 失败反馈含日志/diff | `sidecar/lib/fixfeedback.mjs:57 buildFixFeedback` |
| `fixRounds` 默认 2 / 上限 5 | `sidecar/lib/targetconfig.mjs:407` |
| 7 套适配器 | `sidecar/lib/` 下 `nextjs/nestjs/trpc/graphql/supabase/python/analyzer` |
| 基准 23/23、0 误报、12/12 | `README.md` 精度基准节 + `benchmarks/corpus.json`（12 条标注）+ `scripts/benchmark.mjs` |
| 测试规模 | `sidecar/tests/` 29 个文件 / 355 项、`#[test]` 35 处、`scripts/e2e-*.mjs` 20 套演练 |
| Juice Shop dogfood | `README.md` 已知边界末条 |
| Java 边界 | `sidecar/lib/analyzer.mjs:43 SOURCE_EXT`、`src-tauri/src/core/token.rs:317 LAUNCHERS` |
| 对外统一口径 | `docs/support-matrix.md` |

## 写作提醒（别把这些写进简历）

- 别写「CI 全平台绿灯」这种无凭据结论——可以写「GitHub Actions 三平台自测矩阵通过（附 run id + 提交 SHA）」，并说明它只证明自测矩阵本身。
- 别写「自动修复任意漏洞」或「AI 全自动修复」——准确说法是「5 类候选可尝试生成补丁，须过严格校验与双重验收」。
- 别写「支持任意框架」——准确说法是「7 套适配器 + 未知框架可选 LLM 侦察兜底」。
- 别把外部扫描写成可打真实生产系统——写操作默认关闭、远程仅 HTTPS 且需预声明主机，对外测试以授权为前提。
