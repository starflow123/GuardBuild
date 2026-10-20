# GuardBuild · 桌面安全 Agent

<p align="center">
  <img src="src-tauri/icons/128x128@2x.png" width="120" alt="GuardBuild" /><br/>
  <a href="https://github.com/starflow123/GuardBuild/actions/workflows/selftest.yml"><img src="https://github.com/starflow123/GuardBuild/actions/workflows/selftest.yml/badge.svg" alt="Self-Test" /></a>
</p>

面向 Vibe Coding 开发者的本地安全 Agent：对正在开发的项目执行 **发现 → 复现 → 隔离修复 → 双重验收** 的完整取证工作流——把「感觉有漏洞」变成可复现的证据链，把「让 AI 改代码」变成经过验收的补丁。

- **只报告被真实打穿的漏洞**：每条发现附带真实请求证据与服务端决策归因，而非静态扫描的猜测（proof, not alerts）
- **修复先隔离后落地**：补丁在临时 git worktree 中生成并通过双重验收（攻击失效 + 业务不回归）；写回原工作区需用户授权，带备份、可回滚
- **CI 门禁模式**：无人工交互、按预声明策略授权、结构性禁止写回——只输出报告与已验证补丁

## 工作流原理

| # | 阶段 | 说明 |
| --- | --- | --- |
| 1 | 启动目标 | 执行 `guardbuild.json` 的 `prepare` 前置步骤（依赖安装 / 构建）并启动被检服务；契约未声明 `start` 时自动探测启动方式与端口，就绪以输出匹配或主动 HTTP 探活确认 |
| 2 | 静态线索 | 分析路由与代码产出候选发现（如 IDOR 线索），只作为待实证的线索 |
| 3 | 动态实证 | 用「身份（普通用户/管理员/匿名）× 对象」用例矩阵真实请求服务：攻击用例证明越权/注入可打穿，业务用例验证授权边界完好 |
| 4 | 决策关联 | 目标提供 `/__diag/decisions` 诊断端点时，将每次越权请求归因到具体服务端决策点 |
| 5 | 隔离修复 | 在临时 git worktree 中生成修复补丁，不触碰原工作区 |
| 6 | 双重验收 | 修复后：攻击用例必须全部不再复现，且业务用例必须全部保持通过 |
| 7 | 产物 | `report.json` / `report.md` 报告 + SQLite 证据链（7 张表）；桌面模式可经用户授权写回原工作区 |

**攻击类别**：对象级越权（IDOR）、无鉴权读取、路径穿越、SQL 注入（布尔绕过 / 数据库报错双证据）、命令注入（shell 展开令牌回显，避免输入反射误报）、Supabase 匿名读取与 service_role 暴露。注入与穿越类仅取证，不生成自动修复补丁（按 `vulnerable_unfixed` 阻断并给人工修复指引）。

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
npm run e2e:gate       # CI gate 演练（53 断言，7 轮裁决 + 报告产物）
npm run e2e:blackbox   # 纯黑盒外部扫描演练（22 断言：漏洞/已修复/Cookie 会话/不可达）
npm run e2e:llm        # LLM 接入侦察演练（40 断言，本机 mock DeepSeek，含无密钥磁盘缓存复用轮）
npm run e2e:llm-patch  # LLM 编码代理补丁演练（49 断言，本机 mock：守规矩 / 不守规矩 / 无密钥三轮）
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
- `llm`：可选 LLM 开关——接入侦察（`enabled` / `model` / `maxFiles`）与编码代理补丁（`patch` / `autoVerify` / `patchMaxFiles`），默认全关；启用与安全边界见下两节
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

静态适配器认不出的自定义路由表 / 启动方式，可让 DeepSeek 只做「接入侦察」：读取脱敏后的目录树与少量源码片段，推断启动命令、登录请求形态与可寻址路由。默认关闭，必须显式开启：

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
- 安全边界：只发送目录树与脱敏源码片段，**不发送 `guardbuild.json`（含测试身份）、`.env`、密钥/锁文件**；出站统一走 Host 的 `net.egress`（仅预声明主机 + https）；密钥不写入契约、日志、证据与报告
- 裁决边界：LLM 不判定漏洞、不生成身份；其路由线索只用于定位动态探测目标。未开启 `llm.patch` 时修复阶段跳过 LLM 侦察出的候选（攻击复现后裁决为 `vulnerable_unfixed`，需人工修复）
- 可观测：事件流与视图 `llm` 字段记录 model / 证据文件 / 路由数 / 应用与验证结果 / token 用量；报告 `report.json` 与 `report.md` 的「LLM 接入侦察」段同步记录缓存来源、实际启动/登录验证与被拒绝的启动方式；GUI 增加「LLM 接入侦察」面板
- 侦察缓存：结果写入 `GUARDBUILD_DATA_DIR/scout/<项目哈希>/<证据哈希>.json`，**不写入被检项目**；有效期 7 天、每个项目最多 20 份；缓存键包含模型与证据树/文件内容，源码或契约变化会自动失效；载入时重新跑结构白名单与路由可定位校验，并再次实际启动/登录验证；上次启动验证失败的启动方式会被忽略；缓存只含脱敏契约，不含密钥、提示词或身份凭证
- 无密钥复用：同一项目命中磁盘缓存时，即使未设置 `DEEPSEEK_API_KEY` 也能复用侦察契约并完成实际验证，事件流与视图标记 `cacheSource=disk`
- 环境变量：`DEEPSEEK_API_KEY`（必需）、`DEEPSEEK_BASE_URL`（测试/代理端点）、`DEEPSEEK_MODEL`（缺省 `deepseek-chat`）；Host 启动 Sidecar 时只透传这三个与 `GUARDBUILD_LLM_SCOUT` / `GUARDBUILD_LLM_PATCH`，不会进入目标进程环境

### 可选：LLM 编码代理（补丁意图 + 自动双重验收）

确定性修复模板只覆盖「能识别归属校验位」的 IDOR 形态；真实项目里常见的「先规整参数再取数」等写法模板补不动。开启编码代理后，让 DeepSeek 扮演**编码代理**产出补丁**意图**，由 Sidecar 严格校验、只在隔离 worktree 落地，再自动跑双重验收，通过后才交人工审查：

```json
{
  "llm": { "enabled": false, "patch": true, "autoVerify": true, "patchMaxFiles": 6 },
  "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe", "net.egress:api.deepseek.com"]
}
```

```bash
export DEEPSEEK_API_KEY=...    # 只放环境变量；也可用 GUARDBUILD_LLM_PATCH=1 临时开启
npm run e2e:llm-patch          # 本机 mock DeepSeek 三轮演练，无需真实密钥
```

- 输出形状约束：模型只被允许返回补丁意图 JSON 对象 `{"patches":[{"file":"相对路径","search":"文件中逐字连续原文","replace":"替换后的文本","candidate":"METHOD /path","reason":"一句话"}]}`（JSON 模式、非流式），**不返回整份文件、不返回 diff**。Sidecar 把每条意图规整成 `{ find, replace, count: 1 }` 的精确锚点替换
- 逐条校验关（任一条不过即拒绝该条意图，不影响其余）：结构白名单（只收 `file` / `search` / `replace` / `candidate` / `reason`）→ 目标文件必须等于该候选定位到的源码文件（禁越界改文件）→ 禁改 `package.json` / 锁文件 / `guardbuild.json` / `.env` 与证书私钥类文件 / 配置（yml、toml、ini、conf、sql）/ 测试与 `fixtures` / 构建产物与 `node_modules` 目录 → 锚点须在文件中**唯一**命中（缺失或重复即拒绝）→ 新增内容不得含 `child_process` / `eval` / `new Function` / `rm -rf` 等与修复无关的危险调用 → `search` 与 `replace` 相同（空操作）即拒绝。单会话最多 6 个候选文件（`patchMaxFiles` 可调 1–10），每条意图限制锚点 80 行 / 新增 24 行
- 自动双重验收（`autoVerify`，默认开）：补丁落地后在隔离 worktree 启动修复候选实例，自动跑「攻击用例全部阻断 + 业务用例零回归」。通过 → 进入 `writeback_pending` 交您在界面审查 Diff 并授权写回；未通过 → 终态 `verify_failed`，`report.json` 保留漏洞裁决（`verdict: vulnerable` + `patchStatus: verify_failed`），gate 仍 exit 1 **不放行**，绝不把未验证的补丁交给人工
- 确定性模板补丁语义不变：仍走「人工批准后再验收」的 `patch_review` 流程，`autoVerify` 只作用于编码代理产出的补丁
- 安全边界：提示词只含脱敏后的源码片段（密钥字符替换为 `***`）、候选端点与已复现的攻击证据，**不含 `guardbuild.json` 契约、测试身份口令与 API 密钥**；出站同样走 Host 的 `net.egress`；补丁只写隔离 worktree，gate 模式下原工作区结构性不可写
- 裁决边界不变：LLM 不判定漏洞、不生成身份，也不参与验收裁决——是否放行只由实测证据（攻击阻断 / 业务回归）决定
- 可观测：视图与报告的补丁对象新增 `strategy: "llm-coding-agent"`、`autoVerify`、`llm`（模型 / token 用量 / 采纳与拒绝统计 / 涉及文件与补丁数）；`report.md` 新增「LLM 编码代理（补丁意图）」章节，逐条列出被拒绝的意图与原因；GUI 在补丁面板展示同一份统计
- 无密钥 / 未开启：编码代理整体关闭，行为回落到「模板能补就补，补不动就 `vulnerable_unfixed` + exit 1 交人工」，零模型调用、零外发
- 回归：`npm run e2e:llm-patch`（49 断言，三轮：守规矩模型 → 自动验收通过 exit 1 且全程不进 `patch_review`；不守规矩模型 → 越界与歧义锚点被拒、双重验收拦下 `verify_failed`；无密钥 → 零外发 + `vulnerable_unfixed`），靶场为 `fixtures/llm-patch-shop`（其取数形态经静态校验确认两条确定性模板都补不动）

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

- 探测面：OpenAPI 发现 + 常见路由目录探测；未认证读取、跨用户读取（IDOR，需 ≥2 个普通测试身份）、SQL 注入（错误回显 / 稳定基线布尔盲注）、路径穿越、敏感文件与 actuator 暴露、限流观察。
- 写操作越权（PUT IDOR）默认关闭，避免修改目标数据；显式开启：`guardbuild.json` 的 `blackbox.allowMutation: true` 或环境变量 `GUARDBUILD_BLACKBOX_MUTATE=1`（修改后尽力恢复原值）。
- 登录/身份来自 `guardbuild.json` 的 `login` / `identities`；可加 `blackbox.loginPaths` 补充登录端点候选。表单登录（`login.encoding: "form"`）与 Cookie 会话（`login.cookieAuth: true`，兼容 302 + `Set-Cookie`）同样适用于黑盒模式。
- `blackbox.maxRoutes`（10–200，缺省 60）控制 OpenAPI/目录探测合并后的路由上限；每类攻击的探测候选默认最多 14 条，调低 `maxRoutes` 时同步收紧。
- 桌面端入口：左侧「黑盒外部目标」面板填写已运行目标 URL、选择契约目录后点击「扫描外部目标」；白盒启动流程不受影响。
- 裁决：发现可复现漏洞 → `completed` + `vulnerable_unfixed`，exit 1；无可复现漏洞 → `completed` + `no_findings`，exit 0；目标不可达/执行错误 → `failed`，exit 2（不可达会在一次短超时预检后立即失败，不做整轮探测）。
- 报告：`report.json` / `report.md` 为黑盒版式，含路由发现、登录结果、证据级别与复现 curl；证据中令牌一律为 `***vault:<identity>***` 占位。
- 回归：`npm run e2e:blackbox`（22 断言：漏洞目标 exit 1、已修复目标 exit 0、Cookie 会话目标沿 form 登录 + 302 Set-Cookie 复现 IDOR、不可达 exit 2 + 快速短路、报告一致性与凭证不泄露）。

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
└─ .github/workflows/      自测矩阵（ubuntu-latest + windows-latest）
```

## 已知边界

- 静态路由适配已覆盖：Express 风格、Next.js（App/Pages Router）、NestJS、tRPC、GraphQL、Supabase/PostgREST、Python（FastAPI/Flask/Django + DRF）；NestJS / GraphQL / Python 等形态暂不提供自动补丁（证据成立时按 `vulnerable_unfixed` 阻断并给人工修复指引）
- 取数形态覆盖：`findById`/`findOne`/`findUnique` 等 ORM 单查、Drizzle 链、`dbGet`/`db.get`/`pool.query`、`db.prepare(...).get(...)`、Prisma `$queryRaw`/`$queryRawUnsafe`、Knex `.first()`、`db.raw(...)`；Prisma 标签模板（`$queryRaw` 后接模板字符串）自动参数化，不误报为 SQL 注入
- 注入静态识别基于「请求输入 → 模板/拼接 → SQL或 shell 首实参」的轻量污点传播；动态复现要求目标返回列表行数变化、数据库报错特征或 shell 展开令牌，无法确证时记为 inconclusive 而非漏洞
- Flask/Django 的自定义路由注册、异步视图与中间件级鉴权等边缘形态仍可能漏检；动态复现要求项目能按 `guardbuild.json` 启动，并具备可登录的测试身份
- Windows 全链路已实测；Linux 由 CI 矩阵持续验证（ubuntu-latest + windows-latest），macOS 尚未覆盖
- 已在 OWASP Juice Shop v20.3.0 上完成全链路 dogfood（Windows，真实依赖与启动链）：静态分析 → email 登录 → 越权复现 → 隔离修复 → 双重验收 `patchStatus=verified`；靶点为注入式 IDOR 样例（非 Juice Shop 自身漏洞），据此修复 10 项真实项目接入失败点

## 开发备注

- 无头宿主构建使用 `--no-default-features`（绕过 `gui` feature，Linux 上无需 WebKit 依赖）
- 演练脚本自动解析宿主二进制：`GUARDBUILD_HEADLESS_BIN` > `target/debug` > `target/release`
- gate 超时缺省 15 分钟，可用 `GUARDBUILD_GATE_TIMEOUT_MS` 覆盖

## License

尚未选择开源许可证。在添加 LICENSE 之前，默认保留所有权利。
