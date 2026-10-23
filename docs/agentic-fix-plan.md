# Agentic 修复链路改造 · 执行文档

> 状态：**部分落地**（S1 反馈增强、验收加厚、逐候选归因、S2-lite 只读自查、S3-lite 多候选启动已完成；S2-full 跨文件写权限与 S3-full 自主启动 agent 待拍板/待沙箱加固）
> 记录时间：2026-10-21（落地记录更新至 2026-10-23）
> 起因：讨论「报告 → AI 改代码 → 再攻击验收」的闭环缺口，以及用户提出的三点方案

## 0. 用户诉求（原话要点）

1. 放开权限给 AI 改代码；
2. AI 完整展示改了哪些部分，由用户决策是否执行修改（因为单改一处可能导致项目跑不起来）；
3. 补一个「项目启动 agent」——开发者文件混乱时，让 agent 把项目在沙箱里跑起来，才能进入攻击测试。

## 1. 现状（代码级事实，已逐条核对）

### 1.1 「用户决策是否执行修改」已经存在

- 补丁只落在临时 git worktree，不触碰原工作区（`sidecar/lib/patcher.mjs`）。
- 自动双重验收通过后进入 `writeback_pending`；GUI 点「确认写回」才落地：`src-tauri/src/core/host.rs:1739 approve_writeback()` 校验状态（`host.rs:1764`）与补丁哈希，签发 `via: "user-diff-approval"` 令牌。
- 写回前自动备份，回滚按备份 ID 恢复、冲突文件不覆盖（`src-tauri/src/core/gitops.rs`）。
- gate 模式在 Host 层直接拒绝写回，结构性不可写。

**结论**：不缺「用户决策」这一环，缺的是「用户凭什么决策」——见 §2.1。

### 1.2 多文件补丁本身已支持，真正卡住的是单文件硬规则

- `sidecar/lib/patcher.mjs` 按候选文件逐个调用 LLM，一次会话可改多个文件（实测 geo-monitoring 补丁动过 4 文件 / 60 行）。
- 真正的限制在 `sidecar/lib/llm-patcher.mjs:120`：

  ```js
  if (fileRel.toLowerCase() !== target.toLowerCase()) {
    reject(item, `补丁目标 ${fileRel} 越出本次候选文件 ${target}`);
    continue;
  }
  ```

  即每轮只允许改「该候选定位到的那一个源码文件」，不能碰兄弟模块，不能新建文件。

**结论**：诉求实际等于「放开候选文件之外的文件 + 允许新建文件」，是一条可精确改动的规则，不是重写架构。

### 1.3 最大缺口：agent 的失败反馈太薄

`sidecar/main.mjs:975 buildFixFeedback()` 目前只回传：轮次、原因、`attack_regressed` / `business_regressed`、最多 8 条失败用例（用例名 / 实际响应 / 状态）。

**没有**：验证实例的启动日志尾部、编译与加载报错、上一轮实际落地的 diff、本轮该文件的当前字节。

配套的循环已存在但被这个薄反馈拖住：`fixRounds` 默认 2、上限 3（`sidecar/lib/targetconfig.mjs:384`），gate 恒为单轮。

### 1.4 LLM 默认关闭是设计选择，不是遗漏

- 侦察：`sidecar/main.mjs stageScout()` 需 `llm.enabled=true` 或 `GUARDBUILD_LLM_SCOUT=1`。
- 补丁：`patchEnabled()` = 有 `DEEPSEEK_API_KEY` **且**（`llm.patch=true` 或 `GUARDBUILD_LLM_PATCH=1`）。
- 关闭时零模型调用、零外发，回落到「模板能补就补，补不动 `vulnerable_unfixed` + exit 1」。

确定性流程能覆盖的形态（js/ts/py/graphql/nest/next/trpc/supabase）走静态适配器 + 动态实证，不需要模型；模型只在「静态认不出」或「模板补不动」时才划算。

### 1.5 已知边界（本次讨论暴露的两处）

- 无 Java 适配器：`sidecar/lib/analyzer.mjs:37 SOURCE_EXT` 不含 `.java` → Spring 项目必为 `no_candidates`。
- 无 Java 启动器：`src-tauri/src/core/token.rs:268 LAUNCHERS` 只有 node/npm/npx + Python 生态，不含 java/mvn/gradle → 即使有适配器也起不来。
- 文案缺陷（长期挂账）：`no_candidates`（exit 0，表示未命中覆盖范围）在 GUI 显示成「执行失败」，用户误读为工具坏了。

---

## 2. 用户方案的缺陷

### 2.1 把「完整 diff」当决策依据会失效

问题不是看不懂，是**评审疲劳**：一次修复十几文件上百行 diff，第一次会逐行看，第八次只会扫一眼点确认。此时「用户决策」退化成形式，安全性是假的。

真正的决策依据应是**验收结论**（攻击是否被挡住 / 业务是否回归 / 这处改动为哪条漏洞服务），diff 只在结论可疑时展开。

→ 界面应给「风险画像」而非「一屏 diff」：
- 动了哪些文件，其中哪些是共享文件（被 N 处引用 → 影响面大）；
- 每条漏洞：修复前「打穿」→ 修复后「阻断」的用例对照；
- 被系统驳回的补丁意图及理由；
- diff 折叠在需要细看时才展开。

### 2.2 完全放开权限会切断归因链，产生「假修复」

现在的链条是 `candidate → 定位文件 → 补丁 → 该 candidate 的攻击用例翻转`，所以 `verified` 一词有分量。放开成任意改 + 新建文件后，最危险的失败不是改崩，而是**改对了别的东西**：顺手加了路由守卫、改了错误处理让状态码变化，攻击用例碰巧不再通过，于是报告说「已修复」，漏洞一行没动。这种绿比红更糟。

放开权限必须同时钉死两条：
- **不可碰清单**（在 `patchTargetAllowed` 现有禁改集上继续扩展）：测试文件、攻击用例、`guardbuild.json` 契约、`package.json` / 锁文件 / `requirements.txt`、迁移脚本。理由直白——能改用例就能让用例「通过」。
- **归因硬规则**：验收不看「总体变好」，只看「这条 candidate 的那一发攻击从打穿变阻断，且业务用例零回归」。对不上即不算修复。

### 2.3 顺序错了：先放权限、后补反馈 = 让 agent 在瞎眼状态下扩大爆炸半径

权限是手，反馈是眼。当前眼最缺（§1.3）。若先放手，注定是：跨文件乱改 → 验收不过 → 只收到「没过」两个字 → 再乱改 → 更多文件被污染 → 用户面对无法判断的 diff。

**必须先给眼，再给手。而且「给眼」这一步不需要任何新权限。**

### 2.4 启动 agent 的隐藏代价（同意必要，但它是风险最高的一步）

- **有副作用**：`prepare` / install / build 会往项目里写东西（锁文件、`dist`、`.env`、跑 DB 迁移）。
- **执行任意代码**：今天的 Docker 模式明确不是防恶意代码的边界（README：项目目录读写挂载，「不要用它运行不信任仓库」），启动 agent 意味着在未加固沙箱里执行陌生仓库的命令。
- **成本**：文件混乱时试十几种启动命令是常态，5–15 分钟、几十次模型调用。
- **「起来了」要有精确定义**：不是进程活着，而是 HTTP 可达 + 登录可过 + 发现了可寻址资源；否则后面的攻击全是空转。
- **数据面安全**：必须接临时库 / seed 数据，写操作类用例默认关。

---

## 3. 建议方案（三步，各自可独立交付）

### S1 · 先给眼睛（零新权限，最先做）

落地位置：`sidecar/lib/fixfeedback.mjs`（原 `sidecar/main.mjs:975 buildFixFeedback()` 的薄实现已迁出并加厚）

新增回传内容：
1. 验证实例日志尾部（stdout + stderr 已带 `stream` 标记存进同一个 `RingBuffer`，`src-tauri/src/core/procops.rs:384` 起，取用即可）；
2. 编译 / 模块加载报错（复用 `autostart.mjs` 的 DIAGNOSTICS 归类结果）；
3. 上一轮实际落地的补丁 diff；
4. 本轮该文件的当前字节（脱敏后）。

配套：`sidecar/lib/targetconfig.mjs:384` 的 `fixRounds` 上限 3 → 5（仅 GUI 模式，gate 保持单轮）。

**注意（S1 内含）**：这些日志会同时进入模型提示词与报告，出站前必须过 Host 的脱敏（`src-tauri/src/core/redact.rs`）。已核实：`proc.spawn` 传入的 `resolve_log`（`src-tauri/src/core/host.rs:1134`）对**每一条**日志行都做 `redactor.redact(line, vault)` 并恒返回 `Some`，因此 `RingBuffer` 落的即是脱敏行、`proc.logs` 出宿主即已脱敏（`procops.rs:398` 的 `unwrap_or(原始行)` 分支实际不可达）；取用侧无需再补一道，但报告/视图只回喂**摘要计数与诊断码**，日志原文不进产物。

**落地记录（2026-10-22）**：已实现并合入。反馈构造独立成模块 `sidecar/lib/fixfeedback.mjs`（`buildFixFeedback` + `feedbackDigest`），诊断复用改为 `autostart.mjs` 导出的 `matchDiagnostics()`（返回全部命中而非首个）；`fixRounds` 上限 3 → 5（仅 GUI，gate 仍单轮）。回归：`sidecar/tests/fixfeedback.test.mjs`（7 项：日志/diff/诊断/预算/降级/摘要不含原文）+ `npm run e2e:fix-agent` 21 断言（新增「第二轮反馈带隔离实例真实日志」「带上一轮 diff」「摘要进 fixLoop 轮次记录」）。

**价值**：不碰权限就提高现有单文件补丁的成功率。做完很可能发现，一部分「需要跨文件」的诉求本质是「agent 此前不知道错在哪」。

### 验收加厚 · 攻击变体 + 正向断言（§2.2 的防线，先于放权限落地）

§2.2 说的「假修复」有两种：一是补丁只挡住了我用来复现的那一发写法（换个对象 ID、换个 ID 写法、换个参数通道就绕过），二是攻击碰巧不通过了——路由守卫一刀切全拒、或把人家的返回字段删了来冒充修复。两者都靠「基线用例 + 200 就算过」的验收放过去。

**落地记录（2026-10-22）**：

1. **同源攻击变体（引擎生成，模型不参与编写用例）**：`sidecar/lib/attackvariants.mjs` 从主候选端点派生三条只读轴——他人对象（列表里另挑非 attacker 自有的 ID）、ID 表示法（前导零 / 前后空格 / `+` / `.0`，只保留 `Number(decode(v)) === 原值` 的等价写法）、参数通道（尾部 `:param` 的路径写法补一条 `?param=` 写法）。每候选最多 `MAX_VARIANT_CASES=6` 条，仅挂主候选；tRPC/GraphQL/非 GET 不派生通道变体。
2. **`requiresPreRepro` 规则**：变体在修复前没复现（该目标本就不认这种写法，例如拼 `%20` 被路由直接 404）则**从修复后验收中剔除**，否则「这条路从来不通」会被记成「补丁挡住了」，凭空抬高阻断数。跳过条数进 phase_summary 与报告（`variantPlanned / variantCounted / variantSkipped`）。
3. **正向断言**：本人读用例升级为「200 + 归属本人 + 字段契约不减少」——修复前把 victim 自己看到的字段名集合存进 `ctx._ownerContract`，修复后缺字段即 `FAIL:字段契约缺失 …（不得删减本人可见内容来冒充修复）`；并新增 `business-read-own-victim`（受害者侧本人读），一刀切式守卫会在这里现出原形（403 → 业务回归）。
4. **刻意不做的轴**：PUT/PATCH/DELETE 变体不做。破坏性探针在修复前阶段就会删掉后续变体与业务用例要读的对象，制造自伤式假通过；写用例的成本/风险与收益不划算，理由写进模块头注释而不是塞进开关。
5. **成本**：每阶段最多多 6 条请求（只挂主候选），无请求配额机制、单请求 30s 超时不变，无需重算预算。

回归：`sidecar/tests/attackvariants.test.mjs`（8 项，含变体 ID/路径全集、判定语义、无素材降级、仅主候选派生、victim 正向断言）；`npm run e2e` 36 断言、`npm run e2e:fix-agent` 21 断言（第 1 轮故意漏修时，新增的「变体·他人对象」「变体·ID 前导零」用例被判定为攻击仍可成功并回喂给代理，第二轮补齐）、`npm run e2e:llm-patch` 53 断言全绿。实测证据：`.demo/data/guardbuild.db` 修复前 `/api/orders/5005`、`/5006`、`/05002` 为 `vulnerable`，`%205002`、`5002%20`（blocked，路由不吃）与 `?id=5002`（inconclusive）在修复后行中缺席——正是 `requiresPreRepro` 的过滤结果。

### 补丁归因校验 · 逐候选翻转（§2.2 归因硬规则的落地）

§2.2 的硬规则是「验收不看总体变好，只看这条 candidate 的那一发攻击从打穿变阻断，且业务零回归」。§3 的变体加厚解决的是「同一发攻击换写法绕过」，但汇总口径本身仍然会放过另一种假通过：补丁改的是 A 端点，B 端点的用例因为身份/数据变化顺带不通，`attackBlocked/attackTotal` 照样满，报告就写「已修复」。

**落地记录（2026-10-22）**：

1. **统一键空间**：`planner.mjs` 的 `candKey(c)`（`METHOD epPath`，GraphQL 再附 `graphql.root.field`）改为导出，planner / probe / patcher / attribution 四处共用同一个 key，避免归因表和用例绑定各算各的哈希。probe 在 7 个攻击用例点上打 `candidateKey`（`attack-vertical-escalation` 故意不绑——admin 列表接口本就没有对应代码候选），业务用例不绑。
2. **点名集合**：`createPatch` 返回值新增 `claimedKeys`（模板策略取 `used[].candidateKey`，编码代理策略取 `keyOf` 解析出的候选），main 侧写入 `ctx._claimedCandidates` 并进视图 `patch.claimed`。归因只对「补丁自己声明要修」的入口行使否决权，其余入口的残留状态仍如实呈现但不否决（那本来就不在本轮范围内）。
3. **行为判定优先，静态命中只作线索**：`sidecar/lib/attribution.mjs` 按候选分组修复前用例，只取修复前确实 `vulnerable` 的那些，要求它们在修复后全部 `blocked`；缺修复后用例或判 `inconclusive` 一律 `unverified`。`inconclusive`/缺席算不成立而不是算通过，是刻意选择——拿不到可比证据就是没证明。hunk 定位（`parseDiffHunks` 从 unified diff 的 `@@ -a,b +c,d @@` 取新侧区间，`patchLocality` 按路径尾段与候选绝对路径对齐，Windows `\\?\` 扩展前缀在此消化）输出 `same_file/other_file/no_source` 与距漏洞行行距，进报告但**不参与否决**：真实修复常落在同文件的取数辅助函数甚至上游中间件里，硬否决会误伤好补丁。
4. **顺手补掉一个既有漏洞**：修复前阶段被 `unfixable` 标记跳过的注入/穿越/无鉴权用例，此前在修复后阶段也一并跳过——而编码代理的覆盖范围包含这 5 类候选，于是「代理声明修了 SQLi」可以完全没被复验就进 `verified`。现在 `postPhaseCases()`（纯函数，便于单测）按 `claimedKeys` 决定这些用例是否进修复后阶段：点名了就复跑，没点名仍跳过。
5. **失败回喂与终态复用**：`acceptanceVerdictWithAttribution()` 把 `pass` 与归因结果相与，沿用既有 `verify_failed` 终态与退出码，不新增状态；归因不成立的入口以「归因不成立：`候选` —— `原因`」置入失败列表，`fixfeedback` 另出 `unattributed_candidates` 字段并在指令里写明「列出的入口必须自己完成翻转，改了别的东西让它们顺带不通不算修好」；`report.md` 增「逐候选归因」表（修复前复现用例数 / 修复后判定 / 源码位置 / 补丁命中 / 结论），表内只落仓库相对路径，不含用户绝对路径。

回归：`sidecar/tests/attribution.test.mjs` 13 项（hunk 解析与 `/dev/null` 跳过、行距与同文件判定、全阻断通过、缺修复用例/inconclusive/仍可越权三种不成立、点名未复现、无对应用例的合成行、未点名翻转不影响裁决、业务用例排除、`other_file` 不否决、`\\?\` 绝对路径对齐、空上下文降级）；`postPhaseCases` 3 项 + `buildFixFeedback` 的 `unattributed_candidates` 1 项进 `lib.test.mjs` / `fixfeedback.test.mjs`，单测 252/252。端到端：`npm run e2e` 38 断言（新增「确定性模板补丁点名 2 个入口且 locality 均为 same_file」「写回后复核同样过归因」）、`npm run e2e:llm-patch` 59 断言（r1 `claimed=2 blocked=2`、行距 11/8、表内路径为 `src/app.js`；r2 点名项自证翻转、未点名的越权读记为 `still_vulnerable`）、`npm run e2e:fix-agent` 24 断言（最终轮归因通过 + 反馈摘要含 `unattributed` 计数）全绿。

### S2 · 再给手（配齐约束）

1. **只读工具循环**：agent 修改前可 `list / grep / read` 自查代码（走 Host `project.read` 令牌，返回脱敏内容）。这正对应「让 AI 读源码、按报告找到对应部分去改」。**已落地为 S2-lite（见下节），工具收敛为 `read` / `list`。**
2. **依赖闭包允许集**：以漏洞文件为根，允许改它 import 到的模块 + 新建文件，而不是全仓库任意改。删掉 `llm-patcher.mjs:120` 的单文件硬规则，换成集合判定。
3. **归因校验 + 不可碰清单**（§2.2 两条）。**归因校验已落地**（见上节），不可碰清单在写侧早已生效（`patchTargetAllowed`），读侧另有一层 `toolPathAllowed`。
4. **风险画像 UI**（§2.1），验收通过后才呈现，用户再决定写回。
5. `replay_cases(caseIds)` 按需复跑单条用例（延后，非阻塞项）。

### S2-lite · 只读工具循环（§3 S2 第 1 条的落地）

放「手」之前先放「眼」，而且只放**只读**的那半只手：读只改变模型看得到什么，不扩大写入爆炸半径，§2.2 的归因链与 §2.3 的顺序都不被打断。跨文件写入、新建文件仍属 S2-full，待拍板。

**落地记录（2026-10-22）**：

1. **请求形状与预算**：模型在无补丁时可返回 `{"requests":[{"tool":"read"|"list","path":"相对路径"}]}`。`MAX_TOOL_ROUNDS = 2`（契约 `llm.patchToolRounds` 可配 0–2，0 即关闭自查回落单轮）、每轮最多 4 次调用、单文件 12000 字符、目录 80 条、单次 20 秒超时。没有 `grep`：Host 侧无 ripgrep 能力，`list` + `read` 的组合已足够定位 import 关系，与其造一个语义含糊的假 grep，不如留给 S2-full。
2. **权限边界**：工具实现 `makeReadTools(ctx, wtRoot)` 绑定的是 **worktree 令牌**而非 `project.read`——模型永远读不到原工作区，也读不出 worktree。`toolPathAllowed` 比写侧的 `patchTargetAllowed` 宽（允许看它 import 的模块，这正是自查的意义），但同样拒绝依赖/产物/测试目录，读侧还额外拒绝 `guardbuild.json`、`.env`、锁文件、证书私钥与 `.yml/.toml/.ini/.conf/.sql/.db` 类文件（启动契约里写着测试身份口令），并且只认源码扩展名。`list` 把 Host 返回的绝对路径折成 worktree 相对路径再进提示词，越界条目直接丢弃。
3. **内容处理**：走 Host `fs.read` 的默认脱敏（保险库整值替换 + 规则），实测进提示词的是 `password=***REDACTED***`；读失败或被拒也回喂事实（模型不会反复要同一条路径）；同一 `tool + path` 命中缓存标 `reused`，不重复外发 RPC。
4. **有界往返**：`requestPatchIntent` 由单次请求改为循环，`tool_history` 随轮次累积进同一条提示链（不依赖会话状态）；一轮里同时给 `requests` 与 `patches` 时**以补丁为准**并记一条「忽略自查请求」，避免无界往返；轮次用尽仍无补丁、或请求全被守卫挡下，则诚实写 `failure` 而不是编造补丁。
5. **写权限一位没变 + 可观测**：落地仍限「该候选定位到的那一个源码文件」，仍走 Sidecar 锚点/规模/危险调用校验 → Host 写 worktree → 双重验收 → 逐候选归因。`llmStats.toolRounds / toolCalls` 进视图 `patch.llm`、`report.json`、`report.md` 的「只读自查 N 轮，M 次调用（…）——只读 worktree 内源码，写入范围未变」一行，以及 GUI 补丁面板；**被拒的读取请求与原因进报告，读到的文件内容不进报告**。

回归：`sidecar/tests/llm-tools.test.mjs` 11 项（真实两轮往返、路径守卫拒绝并回喂、轮次上限、requests+patches 补丁优先、无工具时诚实失败、缓存复用、读错误回喂、`parseToolRequests` 形状与配额、`toolPathAllowed` 读写宽窄差异、`makeReadTools` 的 RPC 载荷与令牌与目录折叠、`normalizeLlm` 的 `patchToolRounds` 默认与钳制），单测 263/263。端到端 `npm run e2e:llm-patch` 73 断言新增 r4 轮：模型先请求 `read src/data.js` + `list src` + `read guardbuild.json`，前两者由 Sidecar 在隔离 worktree 代执行、脱敏后回灌，第三者被路径守卫挡下；第二轮提示词 11792 字符里带着真实取数层源码（`export function findOrderById`）与被拒原因，却不含 `alice123` 与任何契约字段；补丁仍是 2 处且只落 `src/app.js`，`toolRounds=1`、3 条 `toolCalls` 逐条留痕，归因 2/2 翻转，工作区未被改动、worktree 已清理。`npm run e2e` 38 断言、`npm run e2e:fix-agent` 24 断言、`npx tsc -b` 同步全绿。

### S3 · 最后做启动 agent

前置条件：比今天更强的沙箱（对恶意仓库的隔离）、命令预算、精确的「运行中」定义、数据面保护（临时库 / seed / 写用例默认关）。攻击面严格限定为项目自己声明并由沙箱启动的那个外部接口。契约与探测结果落盘复用（沿用 scout 的磁盘缓存机制）。

#### S3-lite · 多候选启动契约 + 引擎按序实跑（已落地 2026-10-23）

真正需要「启动 agent」的场景里，模型只给一个启动命令猜错的概率很高；先把「猜错就整轮失败」变成「猜错换下一个」，不放开任何新的执行权限。S3-full（自主试跑、读日志改命令）仍待更强沙箱，不在本轮。

1. **契约形状**：scout 输出从单个 `start` 扩展为 `starts`（1–4 个，按可能性排序，首个即首选），每项字段与旧 `start` 完全一致；旧格式 `start` 仍兼容（并入候选队列）。校验走同一个 `sanitizeStart`——启动器白名单、shell 元字符拒绝、`${GB_PORT}` 端口槽位、cwd 必须是证据内已知目录、就绪超时钳制 5s–120s、env 仅允许 PORT 类键；按 `cmd + args + cwd` 去重（`startSignature`），超过 4 个记警告并截断。模型仍然只提供线索，**哪个能跑由引擎实际启动决定**。
2. **按序实跑与预算**：`tryScoutStartCandidates` 逐个真启动，首个就绪即止；失败码限定 `target_spawn_failed / target_not_ready / port_parse_failed` 才换下一个，其余配置类错误直接中止（换命令救不了坏契约）。总重试预算 `START_RETRY_BUDGET_MS = 120s`，后续候选的 `readyTimeoutMs` 按剩余预算钳制，剩余不足 5s 的候选标记 `budget_exhausted` 跳过；每次失败后清理 docker 容器，不把上一发的进程/端口留给下一发。
3. **全灭回退不是死路**：候选全部失败时回退到确定性自动探测/缺省契约再试一次，并在视图/报告记 `rejectedStart`（首选）与 `rejectedStarts`（全部失败项），缓存写 `verified.start=false`；下次运行整队忽略，避免每次从已知失败的猜测开始。
4. **缓存学习**：实跑验证通过的那个候选写 `workingStart`，下次载入磁盘缓存时提到队首（不新增调用、不需要密钥），其余候选顺序保留。
5. **可观测**：视图 `llm.startAttempts`、`report.json` 与 `report.md` 的「启动候选实际验证」表、GUI 侦察面板逐候选展示 `已就绪 / 失败（诊断码）/ 跳过（预算不足）`。attempt 记录只存命令、诊断码、退出码、耗时与 hint，**不存目标进程原始输出**（避免把目标机密带进报告）。

回归：`sidecar/tests/scout.test.mjs` 11/11（候选按序去重、白名单过滤、上限 4、旧 `start` 兼容、`workingStart` 写回与缓存优先）；`npm run e2e:llm` 50/50，三条实跑轮次覆盖：①首选 `node server.js` 缺依赖失败 → 引擎切到 `node boot.mjs` 就绪并跑完整 gate 复现；②无密钥复用磁盘缓存，`workingStart` 已被提到队首，只启动一次；③全部候选与确定性缺省都失败 → gate 退出码 2 / `target_not_ready`，缓存写入 `verified.start=false` 且不产生 `workingStart`。

### 顺带（不属于 agentic，但影响体感）

- **B 文案**：`no_candidates` 改为「未命中覆盖范围」+ 列出当前支持的栈清单，不再显示成「执行失败」。
  - **落地记录（2026-10-22）**：`no_candidates` 已收口（提交 `34aa8a7`）。本轮补上写回冲突：Host 早已有写回前校验（`src-tauri/src/core/gitops.rs:244` 的 `git apply --check` 预检 + `src-tauri/src/core/host.rs:1039-1049` 的「审批哈希 == 当前 worktree diff」复核，原子拒绝、不存在半写入），所以这一步**没有重复造校验器**，改的是呈现层——`failSession` 把 Host JSON-RPC 的数字码归一为符号码（1007 → `conflict`，取自 `data.code_name`），`coverage.mjs` 为 `conflict` 新增终态措辞（kind=blocked、exit 1 语义、「工作区已变化，补丁未写回」），`report.mjs` 给出「原文件未被修改 + 重跑 / 自行合并 Diff」两条路径。回归：`npm run e2e` 36 断言，新增场景实测「用户改了同一行 → 写回被拒 → 工作区字节不变」。
- **Java/Spring**：双硬边界（§1.5），要么补适配器 + 启动器白名单，要么在接入前明确告知不支持。

---

## 4. 待用户拍板的三个决策

1. 是否允许 agent 修改候选文件之外的文件并新建文件（前提是同时上依赖闭包允许集 + 不可碰清单）？
2. 是否允许 agent 修改前用只读工具自查代码（`list/grep/read`，经 Host 令牌、脱敏返回）？
3. agentic 模式是否只在 GUI 跑，gate 保持确定性单文件单轮不变？（倾向：是。gate 是 CI 门禁，输出必须可复现，不该让模型进去。）

## 5. 不可动摇的不变量（改造过程中必须保持）

- LLM 不裁决漏洞、不生成身份、不参与验收判定；放行只由实测证据决定。
- Sidecar 永不绕过 Host 边界（fs / proc / net / git / vault / redact）。
- 密钥只走环境变量；不进契约、日志、证据、报告，也不进目标进程环境。
- 出站只经 `net.egress`（仅预声明主机 + https）；LLM 与目标服务主机分开授权。
- gate 模式结构性禁止修改被测工作区。
- 攻击只针对沙箱内启动的目标 / 已获授权的外部接口，不测内部源码，不碰未授权真实系统。
