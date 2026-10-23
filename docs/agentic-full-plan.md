# S2-full · S3-full：跨文件写权限与有界启动代理

> 状态：设计已定稿，随本文件起分批实施
> 记录时间：2026-10-23
> 前置：S1 反馈增强、验收加厚（变体+正向断言）、逐候选归因、S2-lite 只读自查、S3-lite 多候选启动均已落地
> 用户拍板：S2-full 与 S3-full 两个都做

## 0. 不变的边界（两批都必须守住）

1. LLM 不裁决漏洞、不生成身份、不参与验收判定；放行只由实测证据决定。
2. Sidecar 永不绕过 Host 边界（fs / proc / net / git / vault / redact）。
3. 写入永远只落在 `data_dir/worktrees/<session>`，原工作区只有用户在 UI 批准且哈希复核通过才被动。
4. 密钥只走环境变量；不进契约、日志、证据、报告，也不进目标进程环境。
5. **模型不编写攻击用例，也不自行拼命令行**——用例由引擎从标注基名派生（已有），命令由引擎从仓库自身声明生成（S3-full 新增）。这条是本轮两个特性共同的收口方式。
6. gate 模式保持确定性：S2-full 与 S3-full 默认关闭，gate 不启用（CI 输出必须可复现，不让模型进裁决链也不让模型进 CI 的执行路径）。

## 1. 现状事实（逐条核对代码，非推测）

| 事实 | 位置 | 对设计的意义 |
| --- | --- | --- |
| 写作用域只有 `worktree.write`，写路径必须是 worktree 内 | `token.rs:247 require_worktree_write_path` | 跨文件写入不需要新作用域种类，只需扩「能否新建文件」这一维 |
| `fs.write` 已支持 `content` 整文件模式，`write_text` 自动建父目录 | `host.rs:851`、`fsops.rs:127` | 新建文件在 Host 侧已可行；缺的是规模上限与创建语义标记 |
| `resolve_in_root_allow_missing` 对最近已存在祖先做 canonicalize | `token.rs:174` | worktree 里指向真实项目的 `node_modules` junction 会被解析到 worktree 外并拒绝，天然阻断「借链接写回原项目」 |
| `diff_capture` 用 `git diff`，不含未跟踪文件 | `gitops.rs:199` | **新建文件当前根本进不了补丁**，必须显式 `git add -N` |
| `git add -N` 产出的 diff 带 `new file mode`，`git apply --check` 与 `apply` 在干净克隆上成功 | 2026-10-23 实测（`/tmp/gt` worktree → `/tmp/gt2` clone） | 新文件的捕获/写回/回滚链路可复用，无需新补丁格式 |
| 回滚已按 `sha_before` 为空删除新增文件 | `gitops.rs:343` | 新文件的撤销无需改动 |
| 单文件硬规则在 `llm-patcher.mjs:229` | `fileRel !== target` 即拒绝 | S2-full 的改动点就是这一条判定换成集合判定 |
| 归因硬规则已存在：点名的候选必须自己完成「打穿→阻断」 | `attribution.mjs`、`postPhaseCases` | 跨文件/新建文件带来的「假修复」风险已有否决权，不必再造 |
| `proc.spawn` 作用域同时含项目根与 worktree 根，启动器白名单 node/npm/npx + Python 生态 + 严格 docker 形状 | `host.rs:513`、`token.rs:262` | S3-full 的 exec 不需要新作用域，复用即可 |
| 确定性 prepare 步骤已经在项目根跑 install/build（gate 也跑） | `main.mjs:864 runPrepare` | 启动代理「执行仓库自带命令」不新增代码执行面，新增的只是「选哪条、跑几次」 |
| scout 契约校验链完整（白名单/元字符/端口槽位/cwd/就绪超时；路由可定位；实跑启动+登录） | `scout.mjs:254 sanitizeStart`、`:828 applyScoutResult` | S3-full 的产出必须仍是这套契约对象，下游零改动 |
| Host 侧无任何预算/配额概念，全部预算在 Node | 全仓库 grep `budget|quota` 在 Rust 侧 0 命中 | 预算先在 Sidecar 收口并留审计；Host 强制是后续项，本文件如实标注 |

## 2. S2-full · 跨文件与新建文件写权限

### 2.1 写集：依赖闭包允许集（不是全仓库）

以「该候选定位到的源码文件」为根，允许集由四类构成：

1. **候选文件本身**（现有权限）。
2. **正向闭包**：候选文件 `import`/`require` 到的仓库内模块，深度 ≤2、文件数 ≤6。
3. **反向引用者**：直接 import 候选文件的模块，深度 ≤1、文件数 ≤4。Nest 的 `app.module.ts` 挂 GlobalGuard、Express 在 `app.js` 里挂中间件都属于这一类——只有正向闭包时这两个场景仍然修不了。
4. **新建文件**：路径必须通过 `patchTargetAllowed`（同一套禁改集），且父目录必须已含有闭包内文件的目录（防止在仓库任意角落造文件），单次会话 ≤3 个、单文件 ≤12000 字符。

图的来源：`analyzeProject` 已经在读每个源码文件（`MAX_FILES=200`，`analyzer.mjs:544`），在同一次读取里抽出相对模块说明符并解析成仓库相对路径，成本为**零额外读取**。解析规则复用 `resolveModuleCandidates`（补扩展名与 `index` 形态），bare specifier（`express`、`@prisma/client`）一律不入图——那指向 `node_modules`，属于不可碰的依赖产物。

配置只能收紧：`llm.patchMaxFiles` 仍是会话级文件上限（默认 6），跨文件不放宽它。

### 2.2 不可碰清单（在现有禁改集上扩展，不新造一套）

`FORBIDDEN_DIR_RE` / `FORBIDDEN_FILE_RE` / `TEST_FILE_RE` 已覆盖：依赖与产物目录、测试目录、`package.json`/锁文件、`guardbuild.json`、配置与数据文件、证书私钥、`.env*`。S2-full 只补两点：
- 新建文件同样走这套判定（`create` 与 `patch` 共用一条路径守卫，不给新建开后门）；
- 迁移脚本目录/文件名（`migrations/`、`prisma/schema.prisma`、`*.sql`）显式纳入禁改集——能改迁移就能改数据面。

理由与 §0.5 同源：能改用例、能改契约、能改依赖清单，就能让验收「通过」。

### 2.3 模型输出协议（扩展，不是重写）

```jsonc
{"patches":[
  {"file":"src/routes/orders.js","search":"…","replace":"…","candidate":"GET /api/orders/:id","reason":"…"},
  {"file":"src/guards/ownership.js","create":true,"content":"export function …","reason":"新增归属校验中间件"},
  {"file":"src/app.js","search":"…","replace":"…","reason":"挂载守卫"}
]}
```

校验顺序（任一条不过即丢弃并留原因，绝不猜测修补）：
1. `file` ∈ 写集（§2.1），且通过不可碰清单；
2. 编辑项：锚点在该文件**隔离副本当前字节**上唯一命中、行数与字符规模受限（沿用 ≤80/≤24/≤4000）、不含脱敏掩码、非空操作、与同文件更早锚点不重叠；
3. 新建项：文件在副本中不存在、内容 ≤12000 字符、不含危险调用（`child_process`/`eval`/`new Function`/`rm -rf`）、不含 `***` 掩码；
4. 跨文件项必须携带 `reason`（进风险画像，人工 review 要能回答「为什么动了这个共享文件」）。

只读自查（S2-lite）与跨文件写相互独立：自查仍只读 worktree，写集仍由引擎计算，模型不能通过读来扩大写集。

### 2.4 Host 侧改动（三处，都是收紧不是放开）

1. `fs.write`：新增整文件与结果的字节上限（`MAX_WRITE_BYTES = 262144`），路径段命中 `.git`/`node_modules`/`dist` 等直接拒绝（不依赖 canonicalize 的隐式行为）；响应加 `created: bool`，事件里区分「新建文件」与「定向替换」。
2. `worktree.write` 作用域加 `allow_create`（`#[serde(default)]`，缺省 false）；`require_worktree_write_path(path, creating)` 在 `creating && !allow_create` 时拒绝。Sidecar 只有在契约/开关启用跨文件模式时才申请带创建的令牌，gate 的授权键仍是 `worktree.write`（策略授权语义不变）。
3. `git.diff` 接受 `intentAdd: [相对路径]`：逐个校验位于该 worktree 内、真实存在、不在禁改目录下，再执行 `git add -N -- <path>`，然后 `diff_capture`。**只加 Sidecar 明确申报的新文件**——不用 `git add -N .`，否则目标进程运行时落下的临时文件、数据库文件会混进补丁。

### 2.5 验收与写回不变

补丁生成后照旧走双重验收（攻击全阻断 + 业务零回归）与逐候选归因；跨文件补丁不新增终态、不改退出码。写回复用 `git apply --check` 预检 + 批准哈希复核；新文件在工作区已存在时 `git apply` 自然失败 → 归一为 `conflict` 终态，原文件不动。

### 2.6 风险画像（人工凭什么决策，而不是一屏 diff）

视图/报告/GUI 的 `patch.scope`：动了哪些文件、每个文件是「候选文件 / 正向闭包 / 反向引用者 / 新建」、每个共享文件的入度（被多少处 import，入度越高影响面越大）、每条被拒意图的原因。逐候选归因表已存在，画像只补「改动范围」这一维。

## 3. S3-full · 有界启动代理

### 3.1 命令菜单由引擎生成（关键收口）

`sidecar/lib/execmenu.mjs` 从仓库自身声明里生成封闭动作集，模型只能报编号：

| 来源 | 生成的动作（命令行由引擎拼装，模型不可改） |
| --- | --- |
| `package.json` `scripts` | `npm run <script>`，仅当脚本名匹配 `^(build\|prepare\|postinstall\|codegen\|prisma:generate…)$` 或安装类；脚本**内容**只作为观察信息展示 |
| `package.json` 存在且有锁文件 | `npm ci`；仅有 `package.json` 时 `npm install`（无参数） |
| `requirements.txt` / `pyproject.toml` | `python -m pip install -r requirements.txt` / `uv sync` |
| `Procfile`、启动探测 `alternatives[]` | 作为**启动候选**（不是 exec），交给现有 `spawnTarget` 实跑 |

裸 `node <任意文件>` 不进菜单：那是真正的任意代码执行，收益不划算。

### 3.2 观察 → 行动循环

```
观察(目录树摘要 + 启动失败诊断码 + 脱敏日志尾部 ≤1200 字符 + 当前候选菜单)
  → 模型选一步：{action:"exec", id} | {action:"start", candidate} | {action:"read"|"list", path} | {action:"giveup", note}
  → Sidecar 执行（Host 令牌与白名单照旧）→ 记录审计 → 再观察
```

预算：步数默认 6、上限 10；单步超时 120s；总墙钟 8 分钟；累计输出字符 60000；同一 `action+id` 重复即短路。任一预算耗尽不伪造成功，终态 `not_started` 并回退到确定性探测/缺省契约（S3-lite 的 `fallbackToDeterministicStart`）。

产出仍是 scout 契约对象（`starts`/`login`/`routes`），必须过同一套 `sanitizeStart` 与四道验证关，且**由引擎实际启动+实际登录判定**；代理的自评不进结论。成功后沿用 scout 磁盘缓存（键含模型与证据内容），并写 `workingStart`。

### 3.3 沙箱与风险的诚实定位

- 隔离的是**写入范围**：exec 在项目根跑 install/build，与今天确定性 prepare 完全同一动作面（`main.mjs:864`，gate 也照跑）；源码写入仍只在 worktree。
- 未加固的是**代码执行**：`npm install` 会跑依赖的生命周期脚本，Docker 模式也不是防恶意仓库的边界（README 已写明）。因此 S3-full 定位为「用户主动开启的 GUI 本地能力」，不默认开、不进 gate、不进 CI；对陌生仓库仍应在 Docker/一次性环境里跑。
- 攻击面不变：只打沙箱内启动的目标的外部接口。

### 3.4 审计

新增 `agent_actions` 表（`db.mjs`）：`session_id / stage(step) / action / subject(菜单 id 或路径或命令形状) / ok / exit_code / duration_ms / budget_remaining / note`。命令行只存**形状**（launcher + 固定参数），不落模型原文；日志尾部不进表、不进报告。报告 `bootstrap` 段给步数、动作序列摘要、最终是否实跑通过、剩余预算。

## 4. 实施批次

| 批次 | 内容 | 验收 |
| --- | --- | --- |
| A1 | Host：`fs.write` 上限与创建标记、`worktree.write.allow_create`、`git.diff.intentAdd` | cargo 单测（新文件 diff 捕获、越界与禁改目录拒绝、超上限拒绝） |
| A2 | Sidecar：`depgraph.mjs` + analyzer 边提取 + `llm-patcher` 集合判定与 create + `patcher.mjs` 写集与逐文件落盘 | 单测：闭包深度/入度/新文件目录约束、create 校验、跨文件锚点唯一、被拒原因 |
| A3 | 靶场 + e2e：`fixtures/crossfile-shop`（正确修法必须新增守卫文件并改宿主文件）、`scripts/e2e-cross-file.mjs` | 端到端：单文件写权限下 `verify_failed`/`no_patchable`，跨文件开启后 `writeback_pending`、归因翻转、工作区未动、worktree 已清理 |
| A4 | 风险画像：`report.json/md` + `bridge.ts` + GUI | tsc + 报告断言 |
| B1 | `execmenu.mjs` + `bootstrap.mjs` 循环与预算 + `targetconfig.bootstrap.*` | 单测：菜单形状、模型自选参数被拒、预算短路 |
| B2 | 接入 `stageScout` 之后 + `agent_actions` 审计 + 报告/GUI | `scripts/e2e-bootstrap.mjs`（mock：先失败 → 选 `npm ci` → 换启动候选 → 实跑就绪） |
| C | 全量回归（单测/e2e 全套/benchmark/cargo/tsc）+ 文档落地记录 + 提交推送 + 重建重启应用 | 与 §5 一致 |

## 5. 明确不做

- 不让模型判定漏洞或判定「修好了」。
- 不让模型编写或修改攻击用例。
- 不让模型拼命令行（exec 只从引擎菜单里选编号）。
- 不在 gate/CI 里启用任何 agentic 能力。
- 不做「全仓库任意改」——写集永远是闭包算出来的有限集合。
- 不补 Java 适配器与 java/mvn/gradle 启动器（那是独立缺口，见 coverage 记录）。

## 6. 落地记录

### S2-full（A1→A4）已落地 · 2026-10-23

| 批次 | 落点 | 实测证据 |
| --- | --- | --- |
| A1 | `src-tauri/src/core/token.rs`（`WorktreeWrite{root, allow_create}`）、`host.rs`（`fs.write` 逐文件上限 + `created` 标记、`intentAdd` 只对 worktree 生效）、`gitops.rs`（`diff_capture` 的 `files[{path,insertions,deletions}]`、`intent_add`） | `cargo test` → 33 passed / 0 failed，含 `new_file_write_requires_allow_create`、`intent_to_add_puts_new_files_into_patch_and_rollback`、`denied_write_dir_segments_block_dependency_and_output_paths`、`worktree_flow_keeps_workspace_untouched` |
| A2 | `sidecar/lib/depgraph.mjs`（`buildImportGraph`/`expandWriteSet`/`inDegree`/`reviveGraph`/`createDirAllowed`）+ analyzer 产出 `depGraph` + `llm-patcher.mjs` 的写集判定、create 校验、`CROSS_FILE_RULES` + `patcher.mjs` 的三类写入与逐文件落盘 | `sidecar/tests/depgraph.test.mjs`、`sidecar/tests/llm-crossfile.test.mjs` |
| A3 | 靶场 `fixtures/crossfile-shop`（越权端点在 `src/routes/orders.js`，正确修法=新建 `src/routes/ownership.js` 并挂进 `src/app.js` 分发处）+ `scripts/e2e-cross-file.mjs` | `npm run e2e:cross-file` → **62/62 断言通过，exit 0**（r1 跨文件补丁→自动双重验收→写回→回滚全链路；r2「只写不挂」被验收拦下；r3 gate 即使 `GUARDBUILD_LLM_CROSSFILE=1` 也结构性禁用） |
| A4 | `patcher.mjs::buildScope` 风险画像 → `main.mjs` 两处 `view.patch.scope` → `report.mjs`（`patch.scope` 进 report.json、`| 写入范围 |` 与「改动范围 / 未改动 / 共享文件入度 / 被拒计数」进 report.md）→ `src/bridge.ts` 的 `ViewPatchScope` → `DiffViewer.tsx` 的 `PatchScopePanel` | `sidecar/tests/scope.test.mjs`（6 条画像 + 1 条报告渲染，全绿）、`npx tsc -b` exit 0、`npm run build` exit 0、`npm run test:sidecar` 296/296、`npm run e2e:cross-file` 62/62 |

画像的取舍：审查者看一条跨文件补丁时最怕两件事——「diff 里只有一屏，实际还动了什么」和「漏洞文件怎么没被改」。
所以画像按角色摊开（candidate / forward / reverse / new），候选文件未改动时显式标 `untouched`（配合「修法落在挂载点，逐候选归因仍按入口翻转判定」），
共享文件给出依赖图入度当影响面，被拒意图给计数。r2 的断言把这套语义钉死：画像里 `newFiles` 有守卫、`closureFiles` 为空，「只写不挂」在人工审查那一屏也看得出来。

踩到的一处真问题（不是测试噪声）：`llm-crossfile.test.mjs` 的 `git.diff` 桩件把 `files` 写成计数 `2`，而 Host 真实返回的是逐文件对象数组。
画像一吃这个字段就炸，暴露出桩件与契约不符——已改成从 diff 头生成 `{path,insertions,deletions}` 数组，并在 `buildScope` 对 Host 响应做形状兜底（外部边界，异常形状不能掀掉整条补丁链路）。

开关与边界（保持 §0）：`llm.patchCrossFile` 默认关，仅 `GUARDBUILD_LLM_CROSSFILE=1` 或契约显式开启；`ctx.gate === true` 时无论配置如何都结构性禁用；
写入只允许候选的依赖闭包写集，新建文件只能落在已扫描过的源码目录；新建走独立的 `worktree.write(allow_create)` 令牌；上限 4 个跨文件、3 个新建、120 行/12k 字符。

### S3-full（B1→B2）已落地 · 2026-10-23

| 批次 | 落点 | 实测证据 |
| --- | --- | --- |
| B1 | `sidecar/lib/execmenu.mjs`（闭合动作菜单：有锁文件给 `npm ci`、无锁文件给 `npm install`，scripts 走白名单且排除 `start`/`test:watch`/`seed:check`，Python 走 `pip install -r` / `uv sync`，按命令形状去重，上限 12 动作 / 8 启动候选，启动候选保留 `readyPattern`/`readyTimeoutMs`/`env`）、`sidecar/lib/bootstrap.mjs`（有界循环：`maxSteps` 1..10 默认 6、`stepTimeoutMs` 5s..600s 默认 120s、`totalBudgetMs` 30s..1800s 默认 480s、`maxOutputChars` 5k..200k 默认 60k、重复动作短路；结局 `started`/`budget_exhausted`/`gave_up`/`llm_unavailable`/`agent_error`/`not_started`）、`sidecar/lib/db.mjs`（`agent_actions` 表 + 插入/查询，每行带剩余预算） | `sidecar/tests/execmenu.test.mjs`（10 条）、`sidecar/tests/bootstrap.test.mjs`（11 条） |
| B2 | `main.mjs::runBootstrapStart`（挂在 `stageReproduce` 的启动失败支路；`bootstrapEnabled(ctx)` 判定；无 LLM 密钥时发 WARN 并返回 null，不冒充代理自救）+ `view.bootstrap` + `report.mjs`（`renderBootstrapSection`/`summarizeBootstrap`）+ `src/bridge.ts`（`BootstrapView`/`BootstrapAction`）+ `src/components/BootstrapPanel.tsx` + `src/App.tsx` | `npm run e2e:bootstrap` → **38/38 断言通过，exit 0**。r1：确定性契约起不来（`ERR_MODULE_NOT_FOUND` → `target_not_ready` + 缺依赖诊断）→ 代理自主 `read scripts/build.js` → 执行菜单编号 2（引擎自己拼的 `npm run build`，构建产物真实落盘）→ 引擎实跑确认就绪（`startSource=bootstrap-agent`）→ 越权证据照旧复现（pre `vulnerable=4`）→ 终态仍按契约 `no_patchable_candidates`（不自动补丁）。r2：模型抗命（编号 99/42 + 自带 `cmd/args/shell`）逐步被拒、引擎一条命令都没执行、诚实失败 `target_not_ready`。r3：gate 即使 `bootstrap.enabled=true` + `GUARDBUILD_LLM_BOOTSTRAP=1` 也结构性禁用（`view.bootstrap` 与报告 `bootstrap` 均为 null、LLM 调用 0 次、被测工作区 `git status` 干净、exit 2 / `failed`） |

成功只能由引擎判定：`outcome=started` 要求 `tryStart` 真的拉起子进程并等到就绪模式命中，模型自陈「起好了」一律不采信；r2 就是这条的实测——模型收手前两步全被拒，会话终态是 `target_not_ready` 而不是「已通过」。
命令走私的处理走「丢弃 + 只留痕字段名」：审计 `sanitize` 行记录 `cmd,args,shell` 与拒因，模型原文（含哨兵串）不进视图、事件、审计、报告、Markdown 任何一处；菜单本身也只给编号与形状，不给身份密码与契约内容。

一处实测教训（不是测试噪声）：靶场 `fixtures/bootstrap-shop` 第一版把手写守卫写成路由块内只有 `if (!auth) return 401`、不引用 `auth.user`，`AUTH_GUARD` 因此判 `hasAuth=false`，候选归到 `no-auth-suspect`（未认证族），planner 只规划匿名读取与越权提权两条用例，而这两条都被应用正确拒绝 → pre `vulnerable=0`、终态 `attack_not_reproducible`（exit 0），真实的跨用户 IDOR 一次都没被打。已把靶场改成与 `llm-patch-shop` 同形的自描述写法，让「唯一障碍是接入」这个前提成立；但这类「块内不引用会话即漏报」本身是一处真实的检测缺口，另立任务跟进。

检测缺口的引擎级修法（不是改靶场）：`sidecar/lib/signals.mjs` 新增 `REJECT_UNAUTH`，识别路由块内的「未登录即拒」分支（`!auth` / `!session` / `!token` / `!jwt` / `!credentials` / `!ctx.user` / `!req.user` / `!currentUser()` 等会话类标识符），`analyzer.mjs` 把它单独记为 `authSource: "reject"`，与 `AUTH_GUARD` 的 `inline` 分开留痕——因为它是「端点确实要登录」的证据，但不是「块内引用了会话身份」的证据。改判后候选进 `readCandidates`（跨用户越权用例）而不是 `unauthReadCandidates`。识别面刻意收窄：裸 `!user` 不算认证守卫（那多数是「对象不存在」检查），否则会把公开端点误判成已登录。
验证：`sidecar/tests/lib.test.mjs` 新增一条三分支对照单测（只有 `if (!auth)` 的块 → `idor-suspect`/`authSource=reject`/入 `readCandidates`；无任何会话判断的块 → 仍 `no-auth-suspect`；`if (!user)` 存在性检查 → 仍 `no-auth-suspect`），Sidecar 单测 **318/318 exit 0**；`npm run benchmark` 不变差（动态召回 17/17、误报 0/17、静态召回 17/17、退出码一致 8/8，含 `clean-shop` 仍 0 候选，说明没有把干净靶场改判出候选）；`npm run e2e:cross-file` 62/62、`npm run e2e:bootstrap` 38/38（pre `vulnerable=4`），headless / blackbox / python / supabase 四套 exit 0。
