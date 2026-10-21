# GuardBuild · 项目经历

> 用途：简历 / 面试用项目经历。分三档：一句话版、简历条目版、面试展开版。
> 数据基准日：2026-10-21，均对照仓库当前代码与产物核实过（见文末「可核验出处」）。

---

## 一句话版

独立设计并实现 GuardBuild——一个「发现 → 沙箱复现 → 隔离修复 → 双重验收」的本地安全 Agent（Tauri + Rust 权限宿主 + 零依赖 Node 编排器，约 3.3 万行），把大模型参与的自动修复变成有真实攻击证据与回归验证背书的产品能力，而非又一个扫描告警列表。

---

## 简历条目版（可直接粘贴）

**GuardBuild · 面向 Vibe Coding 开发者的本地安全 Agent**（独立开发，2026）
技术栈：Tauri 2 / Rust / React + TypeScript / Node.js 22（`node:sqlite`）/ JSON-RPC 2.0 / GitHub Actions

- 设计「最小权限宿主」架构：Rust Host 是唯一系统能力持有者，7 类作用域令牌（`project.read` / `worktree.write` / `proc.spawn` / `net.probe` / `net.egress` / `workspace.write` / `workspace.rollback`）绑定路径、端口与补丁哈希；不可信的 Node 编排器只能通过「申请令牌 → 由 Host 执行」动作，无法绕过边界。Sidecar **零 npm 依赖**，凭证进 Host 保险库、日志全量脱敏。
- 提出并实现 **proof, not alerts** 取证工作流：静态分析只产线索，必须用「身份 × 对象」用例矩阵在沙箱内真实打穿才计为漏洞；每条发现附可复现 curl PoC 与 SQLite 证据链（7 张表），授权诊断端点可把攻击归因到服务端决策点。
- 覆盖 **7 类可复现漏洞**（对象级越权 / 查询参数越权 / 无鉴权读取 / 路径穿越 / SQL 注入布尔+报错双证据 / 命令注入 / Supabase RLS 与 service_role 暴露）与 **7 套框架适配器**（Express、Next.js、NestJS、tRPC、GraphQL、Supabase/PostgREST、FastAPI/Flask/Django-DRF），并识别 10+ 种取数形态（Prisma、Drizzle、Knex、裸 SQL）。
- 打通**自动修复闭环**：补丁只在临时 git worktree 生成，双重验收（攻击用例全阻断 + 业务用例零回归）通过才进 `writeback_pending`，用户审阅 Diff 后授权写回，带备份与冲突安全回滚；CI gate 模式结构性禁止写回、单轮不重试，保证输出可复现。
- 引入 **LLM 双通道且严格限制其裁决权**：接入侦察（未知框架推断启动/登录/路由）与编码代理（5 类候选的补丁意图）。模型输出经结构白名单、锚点唯一命中、禁改文件集、危险调用扫描逐条校验；LLM 不判定漏洞、不生成身份、不参与验收，失败一律回落确定性流程且不自愈中止。
- 建 **精度基准**（8 个标注靶场语料）量化漏报/误报/退出码一致率：当前基线动态召回 17/17、误报 0/17、退出码一致 8/8、零模型调用；含干净对照组靶场验证「动态澄清静态误报」。
- 工程化交付：纯黑盒外部扫描模式（URL 即可、OpenAPI 发现 + 路由爆破、写操作默认关）、受限 `docker run` 容器沙箱、GitHub Action 门禁（三档退出码语义）、无头宿主（Linux 无需 WebKit 依赖）、独立 exe 单文件产物；测试含 13 个 Sidecar 单测文件 + 31 个 Rust 测试 + 6 套端到端演练脚本。
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
8 个标注靶场语料 + 逐靶场的期望复现用例集合，指标是动态召回率、误报率、退出码一致率，任一漏报/误报即基准失败。含一个「干净对照」靶场（归属校验封装在辅助函数里，静态看像漏、运行期真实拒绝），专门用来证明「动态能澄清静态误报」而不是只会喊狼来了。

### 难点（真正花时间的地方）

- **让任意真实项目跑起来**：这是全链路第一道坎，也是失败率最高的地方。做了启动契约自动探测（Procfile / package.json scripts / Python 入口 / 子目录 monorepo）、`${GB_PORT}` 空闲端口槽位（解决服务硬编码端口导致的双实例冲突）、就绪行端口解析（剥 ANSI、行内 JSON、`host:port`、「端口 NNNN」中文形状）、服务无输出时回环 HTTP 探活兜底，以及 13 类启动失败诊断码给出可操作建议。
- **动态复现的判据设计**：命令注入不能用「输入被反射」当证据（大量误报），改成 shell 展开令牌回显；SQL 注入要列表行数变化或数据库报错特征双证据之一；无法确证记 `inconclusive`，不算漏洞。宁可不报也不假报。
- **Windows 全链路**：`.cmd` shim 沿 PATH×PATHEXT 解析、CRLF 锚点匹配、进程树清理、junction 与 worktree 删除互相穿透的坑。

### 我知道它现在不强的地方（诚实边界）

- 语言栈只覆盖 js/ts/python/graphql，**Java/Spring 是双硬边界**（无静态适配器 + 启动器白名单没有 java/mvn/gradle），Spring 项目接入必然空候选。
- 确定性模板补丁只覆盖有明确归属校验插入位的形态（Express/手写路由）；其余形态靠编码代理尝试，补不动就 `vulnerable_unfixed` 交人工。
- 编码代理是**单文件、无工具**的补丁意图生成器：它不能读候选文件以外的代码，失败反馈只有用例名与实际响应，没有日志和上一轮 diff。这是闭环里最薄弱的一环，已经拆解成 S1（补反馈，零新权限）→ S2（只读工具循环 + 依赖闭包允许集 + 归因校验）→ S3（启动 agent，需要先加固沙箱）。
- Docker 沙箱是**运行时隔离**（独立依赖/进程环境），项目目录读写挂载，不构成对恶意仓库的安全边界——所以启动 agent 不能先做。
- CI 三平台自测矩阵存在，但当前结果不可引用为绿（本地同版本全绿，CI 侧失败原因待排查）。

---

## 可核验出处

| 说法 | 出处 |
| --- | --- |
| 3.3 万行量级 | `sidecar`（含测试）20,300 行、`src-tauri/src` 5,735、`src` 1,737、`scripts` 4,730、`shared/protocol.mjs` 461 |
| 7 类作用域令牌 | `README.md` 「安全模型」、`src-tauri/src/core/token.rs` |
| Host 结构性禁止 gate 写回 | `src-tauri/src/core/host.rs:1739 approve_writeback`（要求 `writeback_pending` + 补丁哈希匹配） |
| 单文件硬规则 | `sidecar/lib/llm-patcher.mjs:120` |
| 5 类 LLM 可修候选 | `sidecar/lib/patcher.mjs` `LLM_KINDS` |
| 反馈不含日志/diff | `sidecar/main.mjs:975 buildFixFeedback` |
| `fixRounds` 默认 2 / 上限 3 | `sidecar/lib/targetconfig.mjs:384` |
| 7 套适配器 | `sidecar/lib/` 下 `nextjs/nestjs/trpc/graphql/supabase/python/analyzer` |
| 基准 17/17、0 误报、8/8 | `README.md` 精度基准节 + `benchmarks/corpus.json`（8 条标注）+ `scripts/benchmark.mjs` |
| 测试规模 | `sidecar/tests/` 13 个文件、`#[test]` 31 处、`scripts/e2e-*.mjs` 6 套演练 |
| Juice Shop dogfood | `README.md` 已知边界末条 |
| Java 边界 | `sidecar/lib/analyzer.mjs:37 SOURCE_EXT`、`src-tauri/src/core/token.rs:268 LAUNCHERS` |

## 写作提醒（别把这些写进简历）

- 别写「CI/CD 全平台绿灯」——当前三平台自测失败未修，只可说「本地 Windows 全链路实测 + Linux/macOS 由矩阵覆盖」。
- 别写「自动修复任意漏洞」或「AI 全自动修复」——准确说法是「5 类候选可尝试生成补丁，须过严格校验与双重验收」。
- 别写「支持任意框架」——准确说法是「7 套适配器 + 未知框架可选 LLM 侦察兜底」。
- 别把外部扫描写成可打真实生产系统——写操作默认关闭、远程仅 HTTPS 且需预声明主机，对外测试以授权为前提。
