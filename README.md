# GuardBuild · 桌面安全 Agent

<p align="center">
  <img src="src-tauri/icons/128x128@2x.png" width="120" alt="GuardBuild" /><br/>
  <a href="https://github.com/starflow123/GuardBuild/actions/workflows/selftest.yml"><img src="https://github.com/starflow123/GuardBuild/actions/workflows/selftest.yml/badge.svg" alt="Self-Test" /></a>
</p>

面向 Vibe Coding 开发者的本地安全 Agent：对正在开发的项目执行 **发现 → 复现 → 隔离修复 → 双重验收** 的完整取证工作流——把「感觉有漏洞」变成可复现的证据链，把「让 AI 改代码」变成经过验收的补丁。

- **只报告被真实打穿的漏洞**：每条发现附带真实请求证据与服务端决策归因，而非静态扫描的猜测（proof, not alerts）
- **修复先隔离后落地**：补丁在临时 git worktree 中生成并通过双重验收（攻击失效 + 业务不回归）；写回原工作区需用户授权，带备份、可回滚
- **验收防「只挡住一种写法」和「一刀切假修复」**：除基线用例外，引擎按三条只读轴自动派生同源攻击变体（换他人对象 ID / 换 ID 写法如前导零与首尾空格 / 换参数通道 `:id` ↔ `?id=`，每候选最多 6 条，变体全部由代码生成、模型不参与编写用例），补丁必须把同一越权入口的所有写法一起堵掉才算过；正向断言则要求**受害者本人**仍能读到自己的对象且**字段不比修复前少**，使「挂全局守卫一律 403」「删返回字段让攻击拿不到东西」这类假修复直接计为业务回归。修复前未复现的变体（该目标本就不认这种写法）不参与修复后计数，避免「这条路从来不通」被算成「补丁挡住了」；写/删类破坏性变体不做——修复前探针会删掉后续用例要读的对象，制造自伤式假通过
- **验收落到「每条漏洞自己翻转」**：总体计数变好不算修复——补丁点名的每个入口（`METHOD 路径`）必须自己完成「修复前打穿 → 修复后阻断」，用例被判 `inconclusive` 或没能进入修复后阶段都算归因不成立，整轮判 `verify_failed`。这堵住了「修 A 端点顺带挡掉 B 的某种写法」被记成 B 已修复；被点名的注入/穿越/无鉴权候选（没有自动修复模板、只有编码代理能改）因此也必须复跑自己的用例，不再出现「声明修了却从未被验收」。补丁 hunk 是否落在该候选所在文件、距漏洞行多远会一并呈现，但只作线索不否决——真实修复常写在同文件的取数辅助函数里
- **CI 门禁模式**：无人工交互、按预声明策略授权、结构性禁止写回——只输出报告与已验证补丁
- **AI 修复「先看懂再动手」**：编码代理可在产出补丁前发起只读自查（`read` / `list` 隔离 worktree 里的真实源码，如它要改的文件所 import 的取数层），由 Sidecar 代执行、脱敏后回灌进下一轮提示；读得到不等于写得到——写入范围、逐条校验与双重验收一位没松

## 工作流原理

| # | 阶段 | 说明 |
| --- | --- | --- |
| 1 | 启动目标 | 执行 `guardbuild.json` 的 `prepare` 前置步骤（依赖安装 / 构建）并启动被检服务；契约未声明 `start` 时自动探测启动方式与端口，就绪以输出匹配或主动 HTTP 探活确认 |
| 2 | 静态线索 | 分析路由与代码产出候选发现（如 IDOR 线索），只作为待实证的线索 |
| 3 | 动态实证 | 用「身份（普通用户/管理员/匿名）× 对象」用例矩阵真实请求服务：攻击用例证明越权/注入可打穿，业务用例验证授权边界完好 |
| 4 | 决策关联 | 目标提供 `/__diag/decisions` 诊断端点时，将每次越权请求归因到具体服务端决策点 |
| 5 | 隔离修复 | 在临时 git worktree 中生成修复补丁，不触碰原工作区 |
| 6 | 双重验收 | 修复后：攻击用例（含引擎同源生成的攻击变体）必须全部不再复现，且业务用例（含本人可见性的正向断言）必须全部保持通过 |
| 7 | 产物 | `report.json` / `report.md` 报告 + SQLite 证据链（7 张表）；桌面模式可经用户授权写回原工作区 |

**攻击类别**：对象级越权（IDOR）、无鉴权读取、路径穿越、SQL 注入（布尔绕过 / 数据库报错双证据）、命令注入（shell 展开令牌回显，避免输入反射误报）、SSRF（本机 canary 回连取证）、文件上传（主动内容同源回读取证）、JWT 伪造令牌（alg=none / 无效签名 / 源码密钥，身份回显取证）、业务逻辑与竞态（状态跳步状态回读 / 并发双花副作用标识）、Supabase 匿名读取与 service_role 暴露。自动修复边界：确定性模板只修「带认证但缺归属校验」的 IDOR；开启 LLM 编码代理（`llm.patch`）后，IDOR / 无鉴权 / 穿越 / SQLi / 命令注入五类候选都可尝试生成补丁，仍须通过严格校验与双重验收才计为 `verified`；黑盒模式无源码、Supabase 属平台策略、SSRF / 文件上传 / JWT / 业务逻辑与竞态不提供自动补丁，均只取证并给人工修复指引（`vulnerable_unfixed`）。

**SSRF 取证方式**：静态识别「请求输入 → 服务端 HTTP 客户端 URL」（fetch / axios / got / ky / requests / httpx / urlopen 等，含变量、模板字符串与 f-string 传播），复现时由 Sidecar 在 `127.0.0.1` 随机端口起一次性 canary，把攻击者可控的 URL 参数替换成 canary 地址后发起真实请求。只有目标服务**真的回连 canary** 才判 `vulnerable`（内容级交叉证明，报告保留命中次数）；未回连一律 `inconclusive`，不拿状态码猜。副作用为零、无需外部回调服务；局限：Docker 容器或远程目标访问不到宿主回环地址，这类目标的 SSRF 只能如实记 inconclusive。

**文件上传取证方式**：静态识别接收 multipart 的上传端点（multer / express-fileupload / formidable / busboy / @fastify/multipart / Nest `FileInterceptor` / Python `UploadFile` 等），复现时由引擎生成带随机令牌、内容无害的 `.html` 与 `.svg` 主动内容各上传一次。判 `vulnerable` 需同时满足：上传被接受、能拿到**同源**回读地址、回读内容含本次令牌、响应 `Content-Type` 属主动类型（`text/html` / `image/svg+xml` / JS），且不是 `attachment` 下载。只有状态码没有回读、或回读不到同源地址，一律记 `inconclusive`；拒绝上传记 `blocked`。局限：只证明「主动内容可被同源取回」，不代替浏览器执行验证（存储型 XSS 的实际触发仍需人工确认）。

**JWT 取证方式**：静态按文件识别 JWT 校验缺口——只 `jwt.decode` 不 `jwt.verify`、`algorithms: ["none"]`、验签未固定算法、源码内硬编码签名密钥（`JWT_SECRET = "..."` 或 `jwt.sign/verify` 的字面量实参；`process.env` 引用不算）。复现时对每个受认证端点先发匿名基线请求确认端点确实要求认证，再依次用引擎生成的伪造令牌访问：`alg=none`、HS256 无效签名、以及用**源码里写死的密钥**签发的 HS256。判 `vulnerable` 需伪造令牌被接受（2xx）**且**响应回显攻击者在令牌里植入的标记（`sub` / `username` / `name` / `email`，`gbjwt…`）——两者同时成立才算签名校验被绕过并冒用成功（内容级交叉证明）；令牌被接受但响应不含标记记 `inconclusive`，全部被拒记 `blocked`。局限：不猜弱口令、不做字典攻击，只用源码已写死的密钥；只覆盖「认证绕过」这一可实测子集，OAuth 流程（授权码/隐式/客户端凭据的配置错误）与令牌续期/撤销类问题**不在覆盖内**，需人工审计。

**业务逻辑 / 竞态取证方式**：静态按路由动作识别两类可实测子集——状态流转（`ship` / `deliver` / `complete` / `approve` / `reject` / `activate` / `deactivate` 等，要求明确前置状态）与一次性动作（`refund` / `redeem` / `claim` / `withdraw` / `transfer` / `payout` / `checkout`）。状态跳步：用攻击者自己名下**不满足前置状态**的对象调用流转端点，再经按归属过滤的列表接口**回读状态**；只有「2xx 且状态真的变了」才判 `vulnerable`，409/403 等拒绝记 `blocked`。并发双花：对同一对象并发提交 5 次一次性动作；只有「≥2 次 2xx **且** ≥2 个不同的副作用标识（`refund_id` / `transaction_id` / `claim_id` 等）」才判 `vulnerable`——单纯多次 200 但没有不同副作用标识记 `inconclusive`，避免把幂等成功误报成重复执行。两者都是内容级交叉证明，均无自动修复模板，只给人工修复指引。局限：动作词表是语义白名单，业务自造动词（如 `promote` / `settle`）不在覆盖内；只探测攻击者自己名下的对象，不跨用户改写数据；分布式锁是否正确不单独证伪。

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
npm run e2e            # 主工作流 E2E（36 断言，自动生成 .demo 演示目标；含写回冲突不半写入回归）
npm run e2e:gate       # CI gate 演练（53 断言，7 轮裁决 + 报告产物）
npm run e2e:blackbox   # 纯黑盒外部扫描演练（66 断言：漏洞/已修复/Cookie 会话/不可达/写探测分级）
npm run e2e:ssrf       # SSRF 演练（23 断言：本机 canary 回连取证 + 主机白名单对照）
npm run e2e:upload     # 文件上传演练（23 断言：主动内容同源回读取证 + 类型白名单对照）
npm run e2e:jwt        # JWT 演练（24 断言：alg=none / 无效签名伪造放行取证 + 固定算法强密钥对照）
npm run e2e:bizlogic   # 业务逻辑/竞态演练（29 断言：状态跳步回读 + 并发双花副作用标识，加固后 409/单次成功对照）
npm run e2e:attackplan # 攻击规划代理演练（40 断言，本机 mock DeepSeek：预算重排 + 只认编号 + gate 结构性禁用）
npm run e2e:llm        # LLM 接入侦察演练（50 断言，本机 mock DeepSeek，含候选逐个启动、全灭回退与无密钥磁盘缓存复用）
npm run e2e:llm-patch  # LLM 编码代理补丁演练（73 断言，本机 mock：守规矩 / 不守规矩 / 无密钥 / 先只读自查四轮）
npm run e2e:fix-agent  # 本地修复循环演练（21 断言：首轮漏修 → 失败证据+运行日志回传 → 第二轮通过）
npm run benchmark      # 精度基准（12 个标注靶场：漏报 / 误报 / 退出码一致性）
npm run seed-demo      # 单独生成演示工作区 .demo/vibeshop（供桌面端手动演练）

# 单元测试
npm run test:sidecar   # Sidecar（node --test）
npm run test:rust      # Rust Host
```

## guardbuild.json（目标启动契约）

在被检项目根放置 `guardbuild.json` 声明启动方式、准备步骤、登录契约、测试身份与预声明作用域；文件缺失或字段非法时逐项回落。**`start` 不是必填项**——未声明时引擎自动探测（见下），探测不到才回落缺省 `node server.js`：

```json
{
  "start": {
    "cmd": "node",
    "args": ["server.js"],
    "env": { "PORT": "${GB_PORT}" },
    "readyPattern": "GB_LISTEN",
    "readyTimeoutMs": 20000
  },
  "prepare": [
    { "cmd": "npx", "args": ["tsc"], "timeoutMs": 240000 }
  ],
  "login": {
    "path": "/rest/user/login",
    "bodyTemplate": { "email": "{email}", "password": "{password}" },
    "credentialPath": "authentication.token"
  },
  "responses": { "list": "data.items", "entity": "data.order" },
  "identities": [
    { "name": "alice", "email": "alice@example.com", "password": "alice123", "role": "user" },
    { "name": "admin", "email": "admin@example.com", "password": "admin123", "role": "admin" }
  ],
  "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe"]
}
```

- `start` 自动探测（未声明 `start.cmd` 时）：依次检查 `Procfile`（`web:` 行，`$PORT` 自动改写为 `${GB_PORT}`，只接受宿主白名单启动器）、根 `package.json` scripts（`start > dev > serve > preview`；Next.js 缺 `.next/BUILD_ID` 时 `start` 回退到 `dev`；Vite 自动追加 `--port ${GB_PORT} --host 127.0.0.1`）、根 Python 入口（`uvicorn.run` / `FastAPI()` / `Flask()` / `manage.py runserver`）、子目录入口（`backend` / `server` / `api` 等优先，最多 4 个）。契约未声明 `start.cmd` 时仍可用 `start.env` / `readyPattern` 等字段覆盖探测结果；显式 `start.cmd` 始终优先
- `start.cwd`：启动目录（相对项目根），适配 monorepo 后端位于子目录的项目
- 就绪判定：先看 `readyPattern` 是否在 stdout 出现（自动探测使用通用模式，覆盖 `http://localhost:3000`、`listening on port 3000`、`server started` 等）；服务静默无输出时，若端口已可连通，主动回环 HTTP 探活兜底，避免误报未就绪
- 启动失败诊断：识别 `next_no_build` / `port_in_use` / `missing_env` / `dependency_unreachable` / `db_not_initialized` / `django_migrations` / `command_not_found` / `python_missing_dependency` / `missing_dependency` / `script_missing` / `bind_address` / `permission_denied` / `syntax_error` 等常见原因并给出处置建议，附退出码与日志尾部摘录
- `start`：就绪以 `readyPattern` 在 stdout 出现为准（解析前先剥 ANSI 色码，依次识别行内 JSON `port` → `host:port` → 「端口 NNNN」/ `listening on port NNNN` 文本形状）。端口两种写法任选：`env.PORT=0` 让服务自选端口（要求服务把真实端口打进就绪行）；硬编码端口或打印字面量的服务改用 **`${GB_PORT}` 槽位**——宿主每次 spawn 前分配一个空闲端口注入，`cmd` / `args` / `env` 均可使用（修复阶段会先停止原始实例，验收实例与原始实例不再争用端口）
- `prepare`：目标启动前按序执行的前置命令（安装依赖 / 构建），`cwd` 相对项目根；在「原始工作区」与「隔离 worktree」各执行一次——修复阶段的验收不依赖原工作区的构建产物
- `login`：登录契约——`path` 指定登录端点（优先级高于静态分析候选）；`bodyTemplate` 适配非 `username` 的请求体形状，值支持 `{name}` / `{username}` / `{email}` / `{password}` 占位符；`credentialPath` 支持点路径（如 `authentication.token`），`credentialHeader` / `credentialPrefix` 缺省为 `Authorization` / `Bearer `；`encoding: "form"` 以 `application/x-www-form-urlencoded` 提交；`cookieAuth: true` 表示会话鉴权——登录响应可返回 3xx，`Set-Cookie` 由 Host 收进保险库并在后续请求以 `Cookie` 头注入（`credentialPath` 不填），Cookie 明文不会回到 Sidecar/报告
- `responses`：声明列表 / 单体资源在响应 JSON 中的位置（点路径，如 `data.items`）；不声明时自适应——列表找「顶层数组 → 首个含 `id` 的对象数组」，单体找「首个对象值字段 → 响应自身」；资源名参与用例文案（`order` 显示为「订单」）
- `identities`：支持 `username` / `email` / 自定义 `fields` 三种形状；至少 2 个，否则回退到内置演示身份；`role: "admin"` 的身份用于管理端用例
- `scopes`：仅 CI gate 模式读取，作为「预声明授权」白名单；桌面模式不生效（仍逐次征求用户授权）
- `llm`：可选 LLM 开关——接入侦察（`enabled` / `model` / `maxFiles`）与编码代理补丁（`patch` / `autoVerify` / `patchMaxFiles` / `patchToolRounds`），默认全关；启用与安全边界见下两节
- `docker`：可选容器沙箱（`enabled` / `image` / `containerPort` / `workdir` / `env` / `command` / `readyTimeoutMs`）；启用后目标只经受限 `docker run` 在容器内启动，见下节「Docker 容器沙箱」

**真实项目接入的常见准备**：

- 多数 Node / Python 项目可零启动契约接入（自动探测 `npm run start` / `dev` / `uvicorn` 等）；启动来源与依据见事件流与报告 `start` / `startSource` 字段，接不上时优先看诊断事件里的 `hint`
- 服务依赖构建产物（`tsc` / 打包）→ 把构建命令放进 `prepare`，gate 与桌面模式都会在启动前执行，无需手工预生成
- 登录不是 `/api/login`、不是 `{username, password}`、token 不在顶层 → 用 `login` 契约显式声明；引擎先后尝试「契约声明 → 静态分析候选 → `/api/login`」，成功后固化优先级
- 列表 / 单体不在响应顶层（如 `{ "code": 0, "data": { "items": [] } }`）→ 用 `responses` 契约声明 `list` / `entity` 点路径；不声明时靠自适应探测，形状歧义（多个对象数组）时建议显式声明
- 登录失败会给出归因：凭据错误（401/403）、端点不存在（404/405）、服务端异常（5xx），并提示检查契约对应字段
- Windows 上 `npm` / `npx` 等 `.cmd` shim 自动解析（沿 `PATH` × `PATHEXT` 查找），契约里直接写 `npm` / `npx` 即可
- 服务硬编码端口、启动脚本不支持 `PORT=0`、或就绪行只打印字面量端口 → 契约改用 `${GB_PORT}` 槽位（宿主分配空闲端口注入，解析不到就绪端口时直接回退到分配值）
- 目标项目不是 git 仓库 / 尚无提交基线 → 修复阶段会在创建隔离 worktree 前预检并给出明确指引（`git init && git add -A && git commit -m baseline`）

### 可选：LLM 接入侦察（未知框架兜底）

静态适配器认不出的自定义路由表 / 启动方式，可让 DeepSeek 只做「接入侦察」：读取脱敏后的目录树与少量源码片段，推断 1–4 个候选启动方式、登录请求形态与可寻址路由。默认关闭，必须显式开启：

```json
{
  "llm": { "enabled": true, "model": "deepseek-chat", "maxFiles": 8 },
  "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe", "net.egress:api.deepseek.com"]
}
```

```bash
export DEEPSEEK_API_KEY=...    # 只放环境变量；也可用 GUARDBUILD_LLM_SCOUT=1 临时开启
npm run e2e:llm                # 本机 mock DeepSeek 演练，无需真实密钥
```

- 优先级：显式契约（`start` / `login` / `routes`）> 确定性自动探测 > LLM 侦察；LLM 只补缺，不覆盖已有声明
- 四道验证关：结构白名单 → 路由文件可定位 → 实际启动成功 → 实际登录成功；任一失败都会回退到确定性流程，不中止会话
- 启动候选：侦察按可能性给出 1–4 个启动方式（全部经启动器白名单/参数/端口槽位校验并去重）；引擎按序**真实启动**，首选缺依赖/入口不对时自动换下一个，全部失败才回退自动探测/缺省契约；重试总预算 120 秒。实际验证通过的候选写回缓存并在下次优先，避免每轮都从已知失败的猜测开始
- 安全边界：只发送目录树与脱敏源码片段，**不发送 `guardbuild.json`（含测试身份）、`.env`、密钥/锁文件**；出站统一走 Host 的 `net.egress`（仅预声明主机 + https）；密钥不写入契约、日志、证据与报告
- 裁决边界：LLM 不判定漏洞、不生成身份；其路由线索只用于定位动态探测目标。未开启 `llm.patch` 时修复阶段跳过 LLM 侦察出的候选（攻击复现后裁决为 `vulnerable_unfixed`，需人工修复）
- 可观测：事件流与视图 `llm` 字段记录 model / 证据文件 / 路由数 / 应用与验证结果 / token 用量 / **逐候选启动记录**（命令、结果、诊断、耗时）；报告 `report.json` 与 `report.md` 的「LLM 接入侦察」段同步记录缓存来源、实际启动/登录验证与被拒绝的启动方式；GUI 增加「LLM 接入侦察」面板
- 侦察缓存：结果写入 `GUARDBUILD_DATA_DIR/scout/<项目哈希>/<证据哈希>.json`，**不写入被检项目**；有效期 7 天、每个项目最多 20 份；缓存键包含模型与证据树/文件内容，源码或契约变化会自动失效；载入时重新跑结构白名单与路由可定位校验，并再次实际启动/登录验证；上次整体启动验证失败时不再复用该候选队列，实际验证通过的候选会提到队列最前；缓存只含脱敏契约，不含密钥、提示词或身份凭证
- 无密钥复用：同一项目命中磁盘缓存时，即使未设置 `DEEPSEEK_API_KEY` 也能复用侦察契约并完成实际验证，事件流与视图标记 `cacheSource=disk`
- 环境变量：`DEEPSEEK_API_KEY`（必需）、`DEEPSEEK_BASE_URL`（测试/代理端点）、`DEEPSEEK_MODEL`（缺省 `deepseek-chat`）；Host 启动 Sidecar 时只透传这三个与 `GUARDBUILD_LLM_SCOUT` / `GUARDBUILD_LLM_PATCH`，不会进入目标进程环境

### 可选：LLM 编码代理（补丁意图 + 自动双重验收）

确定性修复模板只覆盖「能识别归属校验位」的 IDOR 形态；真实项目里常见的「先规整参数再取数」等写法模板补不动。开启编码代理后，让 DeepSeek 扮演**编码代理**产出补丁**意图**，由 Sidecar 严格校验、只在隔离 worktree 落地，再自动跑双重验收，通过后才交人工审查：

```json
{
  "llm": { "enabled": false, "patch": true, "autoVerify": true, "patchMaxFiles": 6, "patchToolRounds": 2, "fixRounds": 2 },
  "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe", "net.egress:api.deepseek.com"]
}
```

```bash
export DEEPSEEK_API_KEY=...    # 只放环境变量；也可用 GUARDBUILD_LLM_PATCH=1 临时开启
npm run e2e:llm-patch          # 本机 mock DeepSeek 四轮演练，无需真实密钥
```

- 输出形状约束：模型只被允许返回补丁意图 JSON 对象 `{"patches":[{"file":"相对路径","search":"文件中逐字连续原文","replace":"替换后的文本","candidate":"METHOD /path","reason":"一句话"}]}`（JSON 模式、非流式），**不返回整份文件、不返回 diff**。Sidecar 把每条意图规整成 `{ find, replace, count: 1 }` 的精确锚点替换
- 只读自查（agent 的「眼睛」，`patchToolRounds` 默认 2、上限 2）：所提供的源码不足以定位修法时（取数层、鉴权中间件、共享辅助函数在别的文件里），模型可先返回 `{"requests":[{"tool":"read","path":"src/db.js"},{"tool":"list","path":"src"}]}`，由 Sidecar 用**隔离 worktree 的只读令牌**代为执行，把脱敏后的内容回灌进下一轮提示再要补丁。守卫：只能 `read` / `list`，路径不得越出 worktree，依赖/产物/测试目录与依赖清单/锁文件/`guardbuild.json`/`.env`/证书私钥/数据库与配置类文件一律拒绝（启动契约里写着测试身份口令），只认源码扩展名；每轮最多 4 次调用、单文件 12000 字符、目录 80 条，重复请求走缓存，轮次用尽仍无补丁则诚实记「未产出补丁」而不是编造。**写权限一位没变**——自查只改变模型看得到什么，落地仍限候选文件、仍由 Sidecar 校验 + Host 写入 + 双重验收；被拒的读取请求连同原因回喂给模型，并在报告里逐条留痕
- 逐条校验关（任一条不过即拒绝该条意图，不影响其余）：结构白名单（只收 `file` / `search` / `replace` / `candidate` / `reason`）→ 目标文件必须等于该候选定位到的源码文件（禁越界改文件）→ 禁改 `package.json` / 锁文件 / `guardbuild.json` / `.env` 与证书私钥类文件 / 配置（yml、toml、ini、conf、sql）/ 测试与 `fixtures` / 构建产物与 `node_modules` 目录 → 锚点须在文件中**唯一**命中（缺失或重复即拒绝）→ 新增内容不得含 `child_process` / `eval` / `new Function` / `rm -rf` 等与修复无关的危险调用 → `search` 与 `replace` 相同（空操作）即拒绝。单会话最多 6 个候选文件（`patchMaxFiles` 可调 1–10），每条意图限制锚点 80 行 / 新增 24 行
- 自动双重验收（`autoVerify`，默认开）：补丁落地后在隔离 worktree 启动修复候选实例，自动跑「攻击用例（含引擎派生的同源变体）全部阻断 + 业务用例（含本人可见性与字段契约的正向断言）零回归」。通过 → 进入 `writeback_pending` 交您在界面审查 Diff 并授权写回；未通过 → 终态 `verify_failed`，`report.json` 保留漏洞裁决（`verdict: vulnerable` + `patchStatus: verify_failed`），gate 仍 exit 1 **不放行**，绝不把未验证的补丁交给人工
- 修复循环（仅本地/GUI，`fixRounds` 默认 2、上限 5）：验收未通过时，把失败轮次的现场作为 `previous_attempt` 回传给编码代理——失败用例（用例名 / 实际响应 / 回归计数）+ 修复后隔离实例的真实日志尾部（经 Host `proc.logs`，每行入缓冲前已按保险库脱敏）+ 命中的启动/运行诊断码（复用自动接入的诊断规则表）+ 上一轮实际落地的 diff，然后从 HEAD 重新生成补丁并丢弃失败轮 worktree；每轮独立记录补丁 hash、验收裁决与「回喂了什么证据」的摘要（只记计数与诊断码，不含日志原文）。gate 模式始终单轮、不重试，避免 CI 里反复外发与耗时
- 确定性模板补丁语义不变：仍走「人工批准后再验收」的 `patch_review` 流程，`autoVerify` 只作用于编码代理产出的补丁
- 安全边界：提示词只含脱敏后的源码片段（密钥字符替换为 `***`）、候选端点与已复现的攻击证据，**不含 `guardbuild.json` 契约、测试身份口令与 API 密钥**；只读自查同样只走 worktree 只读令牌 + 路径白名单 + Host 脱敏，读到的内容进提示词但不进报告（报告只记 `tool / path / ok / 字符数或条目数 / 被拒原因`）；出站同样走 Host 的 `net.egress`；补丁只写隔离 worktree，gate 模式下原工作区结构性不可写
- 裁决边界不变：LLM 不判定漏洞、不生成身份，也不参与验收裁决——是否放行只由实测证据（攻击阻断 / 业务回归）决定
- 可观测：视图与报告的补丁对象新增 `strategy: "llm-coding-agent"`、`autoVerify`、`llm`（模型 / token 用量 / 采纳与拒绝统计 / 涉及文件与补丁数 / `toolRounds` + `toolCalls` 只读自查留痕）、`fixLoop`（`maxRounds` / `attempts` / `resolvedRound` / 逐轮 `verdict` 与失败用例）；`report.md` 新增「LLM 编码代理（补丁意图）」章节（含「只读自查 N 轮，M 次调用」一行）与逐轮修复循环记录，并逐条列出被拒绝的意图与原因；GUI 在补丁面板展示同一份统计与轮次
- 无密钥 / 未开启：编码代理整体关闭，行为回落到「模板能补就补，补不动就 `vulnerable_unfixed` + exit 1 交人工」，零模型调用、零外发
- 回归：`npm run e2e:llm-patch`（73 断言，gate 四轮：守规矩模型 → 自动验收通过 exit 1 且全程不进 `patch_review`；不守规矩模型 → 越界与歧义锚点被拒、双重验收拦下 `verify_failed`；无密钥 → 零外发 + `vulnerable_unfixed`；先只读自查的模型 → read 取数层 + list 目录被代执行并脱敏回灌、read `guardbuild.json` 被路径守卫拒绝，补丁仍只落候选文件且逐候选归因通过），靶场为 `fixtures/llm-patch-shop`（其取数形态经静态校验确认两条确定性模板都补不动）；`npm run e2e:fix-agent`（24 断言，本地模式两轮：首轮故意漏修 → 第二轮收到失败用例 + 隔离实例日志尾部 + 上一轮 diff 后补齐 → `writeback_pending`，含失败轮 worktree 清理与逐轮审计）

## 精度基准（固定标注靶场）

`npm run benchmark` 对 `benchmarks/corpus.json` 中的标注靶场逐个运行真实 gate，量化检测能力而不是只看单个 e2e 是否通过：

- 语料字段：`expectedExit`（期望退出码）、`expectedVulnerableCases`（期望复现的攻击用例，未命中即漏报）、`expectedStatic`（期望静态候选，仅统计召回）、`expectedOutcomes`（可选，期望裁决）
- 指标：攻击用例**动态召回率**、**误报率**（被判 vulnerable 但不在标注集合内的用例；干净靶场出现任何 vulnerable 都算误报）、**退出码一致率**、静态召回率（诊断用）
- 判定：任一靶场漏报、误报、退出码不一致或执行失败，基准即以非零码退出；新增适配器/探测能力时在语料追加标注条目并保持全绿
- 干净对照：`fixtures/clean-shop` 的对象接口把归属校验封装在辅助函数中（静态看起来可疑、运行期真实拒绝），用于验证「动态澄清静态误报」与 exit 0 路径
- 产物：`.benchmark/benchmark-report.json` / `.benchmark/benchmark-report.md`（逐靶场漏报、误报、静态命中与裁决）；CI 每次自测都会执行并上传
- 当前基线（2026-10-24）：12 个靶场 · 动态召回 23/23 · 误报 0/23 · 退出码一致 12/12 · 静态召回 23/23 · 零模型调用

## 纯黑盒外部扫描（已运行 / 沙箱中的目标）

不读源码、不启动本地服务、不生成补丁：只对**已运行**的目标发起外部 HTTP 请求并取证。所有请求仍经 Host（回环走 `net.probe`，远程仅 HTTPS 走 `net.egress`），登录令牌由 Host 保险库注入，Sidecar 不见明文。

```bash
# 本机回环目标（项目目录只用于读取 guardbuild.json 的 login/identities 与报告元信息）
guardbuild-headless --url http://127.0.0.1:3000 \
  --project ./my-project --gate --report ./guardbuild-report

# 远程目标：必须 https，且 gate 需在 guardbuild.json 预声明具体主机
#   "scopes": ["net.egress:staging.example.com"]
guardbuild-headless --url https://staging.example.com --project ./my-project --gate
```

- 探测面（每个开关都会写进报告的「本轮攻击面」，GUI 同词）：OpenAPI 发现 + 常见路由目录探测（含管理端点命名猜测）；未认证读取、跨用户读取（IDOR，需 ≥2 个普通测试身份）、垂直越权（普通登录身份访问管理端点，有管理身份时做交叉证明，用于区分「端点不存在」与「正确拒绝」）、SQL 注入（错误回显 / 恒真恒假差分 / **数字语境** `1 OR 1=1` 三段差分 / 单对象条件绕过）、路径穿越（明文 + 二次编码 / 变形编码绕过）、敏感文件与 actuator 暴露、限流观察。
- 写操作越权默认关闭，避免修改甚至销毁目标数据，分两级显式开启：
  - 跨用户 PUT/PATCH 与匿名写入：`blackbox.allowMutation: true` 或 `GUARDBUILD_BLACKBOX_MUTATE=1`（修改后按归属人身份尽力恢复原值，恢复未确认会写进证据）。
  - 跨用户 DELETE 不可回滚，需在上一级之外再加 `blackbox.allowDestructive: true` 或 `GUARDBUILD_BLACKBOX_DELETE=1`。
  - 两类判定都不看状态码：写类以「归属人复核字段值确实被改」为准，DELETE 以「归属人复读对象是否消失」为准；请求被接受但数据未动只记 `inconclusive`，既不记漏洞也不记「已防住」。匿名写入的 canary 由归属人复读证明落库，随后尽力匿名删除自清理。
- 登录/身份来自 `guardbuild.json` 的 `login` / `identities`；可加 `blackbox.loginPaths` 补充登录端点候选。表单登录（`login.encoding: "form"`）与 Cookie 会话（`login.cookieAuth: true`，兼容 302 + `Set-Cookie`）同样适用于黑盒模式。
- `blackbox.maxRoutes`（10–200，缺省 60）控制 OpenAPI/目录探测合并后的路由上限；每类攻击的探测候选默认最多 14 条，调低 `maxRoutes` 时同步收紧。注入/穿越各有独立请求预算（字符串 140 / 数字 70 / 穿越 120），预算用尽在报告里明说而不是静默漏跑。
- **攻击规划代理（M2，默认关闭）**：路由数超过每类探测预算时才启用，把「谁先进预算」交给模型。开关为 `blackbox.attackPlan: true`（或对象形式 `{enabled, maxPicks, rounds}`，`rounds` 1–2、`maxPicks` 1–16）或环境变量 `GUARDBUILD_LLM_ATTACKPLAN=1`；**gate/CI 结构性禁用**，只能在交互模式用。硬边界：模型只能从引擎给出的「预算外 GET 路由菜单」里挑编号，不能指定 URL/方法/参数/载荷/请求头（出现即丢弃，只在审计里留字段名）；第二轮只回灌上轮的「路由 + 用例 + 裁决」压缩视图，不回传响应体；模型原文不入视图、事件与报告；漏洞判定仍只由实跑证据给出。
- 回归：`npm run e2e:attackplan`（40 断言 / 6 轮：默认关闭时诚实漏报、开启后把预算外的 `/api/contracts` 与 `/api/audit` 提进队列并复现 IDOR + SQLi、`rounds=1` 归因、走私字段丢弃、非法编号回退、gate 下零调用零事件），靶场为 `fixtures/queue-shop`。
- 桌面端入口：左侧「黑盒外部目标」面板填写已运行目标 URL、选择契约目录后点击「扫描外部目标」；白盒启动流程不受影响。
- 裁决：发现可复现漏洞 → `completed` + `vulnerable_unfixed`，exit 1；无可复现漏洞 → `completed` + `no_findings`，exit 0；目标不可达/执行错误 → `failed`，exit 2（不可达会在一次短超时预检后立即失败，不做整轮探测）。
- 报告：`report.json` / `report.md` 为黑盒版式，含路由发现、登录结果、证据级别与复现 curl；证据中令牌一律为 `***vault:<identity>***` 占位。
- 靶场：`fixtures/wide-shop`（管理端点只校验登录、订单读写删无归属校验、留言板匿名写删、`?year=` 数字拼 SQL、`?name=` 二次编码穿越），`GB_WIDE_HARDENED=1` 为整体加固版，用于「不该报」那一轮。
- 回归：`npm run e2e:blackbox`（66 断言 / 8 轮：legacy-shop 漏洞 exit 1、已修复 exit 0、Cookie 会话复现 IDOR、不可达 exit 2 + 快速短路；wide-shop 默认探测只见无副作用族、`allowMutation` 补出 PUT/PATCH + 匿名写、再加 `allowDestructive` 补出 DELETE、加固版零 finding 且四类攻击全记 blocked）。断言按 caseId 用例集合而不是 finding 条数，新增探测族漏跑会被抓住。

## Docker 容器沙箱（目标进程隔离）

在 `guardbuild.json` 中声明 `docker`，目标服务会通过受限的 `docker run` 在 Linux 容器内启动；攻击仍只针对映射到宿主回环端口的 HTTP 接口，Sidecar 不进入容器、不读取容器内文件。

```json
{
  "start": {
    "cmd": "node",
    "args": ["server.js"],
    "env": { "PORT": "${GB_PORT}", "HOST": "0.0.0.0" }
  },
  "docker": {
    "enabled": true,
    "image": "node:20-alpine",
    "containerPort": 3000,
    "workdir": "/app",
    "env": { "NODE_ENV": "test" },
    "readyTimeoutMs": 60000
  }
}
```

- 实际启动形状：`docker run --rm --init --name guardbuild-<session>-<role>-<n> -p 127.0.0.1:<宿主端口>:<containerPort> -v <项目目录>:<workdir> -w <workdir> -e ... <image> <start.cmd/start.args>`；`command` 可整体覆盖容器内命令。
- 端口：容器内固定监听 `containerPort`（`start.env.PORT` 会被强制覆盖为该值），宿主端口每次动态分配且只绑定 `127.0.0.1`；就绪判定为对宿主端口的 HTTP 探活（容器日志仅用于失败诊断）。
- 挂载：只允许把本次启动目录（项目根或隔离 worktree）挂载到容器 `workdir`，且 `-w` 必须与挂载点一致；镜像需自带运行时与依赖（`prepare` 仍在宿主机执行）。
- Host 白名单：只接受 `docker run/rm/stop/version`；`run` 仅允许 `--rm`、`--init`、`--name guardbuild-*`、`-p 127.0.0.1:<宿主>:<容器>`、`-v <cwd>:<path>[:ro|rw]`、`-w`、`-e KEY=VALUE`，并拒绝 `--privileged`、host 网络、`--mount`、`--env-file`、`--volumes-from`、任意宿主目录挂载与后台 `-d`。
- 清理：会话结束、失败或中止时对每个容器执行 `docker rm -f`；`docker.enabled=true` 但配置非法时直接报 `docker_config_invalid`，绝不回退到宿主机直接运行。
- 边界：容器用于**运行时隔离**（独立依赖/进程环境，目标不会碰宿主全局环境），项目目录仍以读写方式挂载、可能被目标进程写入；它不构成对恶意项目代码的安全边界，不要用它运行不信任仓库。
- 回归：`npm run e2e:docker`（需要本机 Docker 与 `node:20-alpine`；未检测到 Docker 时自动跳过）。

## CI 门禁接入（GitHub Actions）

```yaml
- name: GuardBuild Gate
  uses: starflow123/GuardBuild@master   # 引用前建议固定到 tag 或 commit
  with:
    project: .                # 目标项目路径（可含 guardbuild.json）
    report-dir: guardbuild-report
    # data-dir: guardbuild-evidence
    # url: http://127.0.0.1:3000   # 可选：对已运行目标做纯黑盒扫描（不读源码/不写回）
```

退出码可直接决定 job 成败：

| 退出码 | verdict | 含义 |
| --- | --- | --- |
| 0 | `no_candidates` / `not_reproducible` | 无漏洞证据 |
| 1 | `vulnerable`（附已验证补丁）/ `vulnerable_unfixed` | 漏洞证据成立：`patchStatus: verified`（通过双重验收）、`verify_failed`（修复未通过验收，附证据），或 `vulnerable_unfixed`（攻击已复现但候选无可自动修复端点，需人工修复） |
| 2 | `failed` / `aborted` / `timeout` | 执行失败（契约 / 环境 / 内部错误 / 超时 / 中断） |

- 输出：`verdict`、`exit-code`、`patch-hash`；报告目录含 `report.json`、`report.md`、`gate.json`（GB_GATE 裁决行）、`gate.log`
- **exit 0 / 1 都是完成取证的正常终态**：`no_candidates` 表示项目形态未命中当前覆盖范围（已覆盖的漏洞类别与框架形态、以及暂无适配器的形态由 `sidecar/lib/coverage.mjs` 统一给出，并写进报告「结论与建议」），`not_reproducible` 表示静态有候选但攻击在真实实例上打不通；两者都**不是执行失败**，桌面界面按中性提示渲染（状态标签分别为「未命中覆盖范围」「未发现可复现漏洞」），内部仍记为 error 终态以便会话槽位释放与 gate 判定
- **写回预检被拒也不是执行失败**：授权写回时若原工作区已变化，Host 在 `git apply --check` 阶段原子拒绝（先预检后落盘，不会写到一半）。Sidecar 把 Host 的 JSON-RPC 数字码归一为符号码 `conflict`，界面呈现「补丁未写回 · 工作区已变化」而非「执行出错」，报告明确写出原文件未被修改、补丁仍在隔离 worktree，并给出「按当前代码重跑会话」与「自行合并报告中的 Diff」两条落地路径
- gate 语义：无人工交互；作用域仅按 `guardbuild.json.scopes` 预声明签发（审批留痕 `via: gate-policy`）；`workspace.write` 被结构性禁止，**不修改被测工作区**，只输出已验证补丁供人工应用

## 安全模型

- **作用域令牌**：`project.read`（限定根目录）/ `worktree.write`（仅临时工作树）/ `proc.spawn`（可执行与参数白名单）/ `net.probe`（仅回环）/ `net.egress`（仅预声明的 HTTPS 主机，LLM 接入侦察用）/ `workspace.write`（绑定补丁哈希，仅 UI 批准后签发）/ `workspace.rollback`（绑定备份 ID，仅 UI 触发）
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
└─ .github/workflows/      自测矩阵（ubuntu / windows / macos latest）
```

## 分发打包（本地构建 NSIS 安装器）

```bash
npm run runtime:prepare   # 把当前 Node（>= 22.5）复制到 src-tauri/runtime
npm run app:dist          # 构建带资源映射的 NSIS 安装器
npm run e2e:package       # 分发布局演练：PATH 中没有 node 也能跑通 gate
```

- 产物：`src-tauri/target/release/bundle/nsis/GuardBuild_<version>_x64-setup.exe`（currentUser 安装、中英双语）。安装目录含 `guardbuild.exe`、`guardbuild-headless.exe`、`runtime/node.exe`、`sidecar/`、`shared/`；Host 优先使用随包 node，缺失时才回退 PATH。
- **默认未签名**：会触发 SmartScreen。设置 `GUARDBUILD_SIGN_CERT_THUMBPRINT`（signtool 证书指纹）或 `GUARDBUILD_SIGN_COMMAND`（必须含 `%1`）后重新构建即可接入签名；时间戳默认 `http://timestamp.digicert.com`。
- 首次构建需要 Tauri 下载 NSIS 工具链（缓存于 `%LOCALAPPDATA%\tauri\NSIS`）；受限网络可预先放置 `Bin/makensis.exe` 与 `Plugins/x86-unicode/additional/nsis_tauri_utils.dll`，之后可离线构建。

## 已知边界

- 静态路由适配已覆盖：Express 风格、Next.js（App/Pages Router）、NestJS、tRPC、GraphQL、Supabase/PostgREST、Python（FastAPI/Flask/Django + DRF）；确定性模板补丁只覆盖 Express / 手写路由等有明确归属校验插入位的形态，NestJS / GraphQL / Python 等暂不提供确定性模板补丁；开启 LLM 编码代理后这些形态的候选同样会进入编码代理尝试（须定位到源码文件，仍以双重验收为准），否则证据成立时按 `vulnerable_unfixed` 阻断并给人工修复指引
- 取数形态覆盖：`findById`/`findOne`/`findUnique` 等 ORM 单查、Drizzle 链、`dbGet`/`db.get`/`pool.query`、`db.prepare(...).get(...)`、Prisma `$queryRaw`/`$queryRawUnsafe`、Knex `.first()`、`db.raw(...)`；Prisma 标签模板（`$queryRaw` 后接模板字符串）自动参数化，不误报为 SQL 注入
- 注入静态识别基于「请求输入 → 模板/拼接 → SQL或 shell 首实参」的轻量污点传播；动态复现要求目标返回列表行数变化、数据库报错特征或 shell 展开令牌，无法确证时记为 inconclusive 而非漏洞
- Flask/Django 的自定义路由注册、异步视图与中间件级鉴权等边缘形态仍可能漏检；动态复现要求项目能按 `guardbuild.json` 启动，并具备可登录的测试身份
- Windows 全链路已实测；Linux / macOS 由 CI 矩阵持续验证（ubuntu-latest + windows-latest + macos-latest）
- 完整支持矩阵、适用场景与不支持项见 [`docs/support-matrix.md`](docs/support-matrix.md)；对外介绍/简历文案先按其中的「不可说」四项自查
- 已在 OWASP Juice Shop v20.3.0 上完成全链路 dogfood（Windows，真实依赖与启动链）：静态分析 → email 登录 → 越权复现 → 隔离修复 → 双重验收 `patchStatus=verified`；靶点为注入式 IDOR 样例（非 Juice Shop 自身漏洞），据此修复 10 项真实项目接入失败点

## 开发备注

- 无头宿主构建使用 `--no-default-features`（绕过 `gui` feature，Linux 上无需 WebKit 依赖）
- 演练脚本自动解析宿主二进制：`GUARDBUILD_HEADLESS_BIN` > `target/debug` > `target/release`
- gate 超时缺省 15 分钟，可用 `GUARDBUILD_GATE_TIMEOUT_MS` 覆盖

## License

尚未选择开源许可证。在添加 LICENSE 之前，默认保留所有权利。
