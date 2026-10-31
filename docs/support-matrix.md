# GuardBuild 支持矩阵与对外口径

> 数据基准日：2026-10-24（对照仓库代码与基准产物核实）。
> 用途：对外介绍、客户答疑、简历/宣传文案的统一事实来源。**任何对外说法先按本文自查。**

## 一句话定位

GuardBuild 是一个面向 Vibe Coding 开发者的本地安全 Agent：先启动项目，用真实身份与真实对象在沙箱内打穿接口，拿到证据后才判定漏洞；修复在临时 git worktree 内生成，必须通过「攻击失效 + 业务不回归」双重验收。

它是 **API 越权/注入/认证类漏洞的 CI 门禁与复现工具**，不是通用漏洞扫描器，也不替代完整渗透测试。

## 产品形态

| 形态 | 入口 | 说明 |
| --- | --- | --- |
| 桌面应用 | `npm run app:dev` / 构建后的 `guardbuild.exe` | 交互式：启动、攻击、报告、Diff 审阅、授权写回 |
| 无头 gate | `guardbuild-headless --project <dir> --gate` | 无人工交互、按契约预声明授权、**结构性禁止写回**、退出码决定 CI 成败 |
| GitHub Action | `uses: starflow123/GuardBuild@master` | 在 CI 内跑 gate，输出 `verdict` / `exit-code` / `patch-hash` |
| 纯黑盒 | `--url http://127.0.0.1:3000` 或 `--url https://staging.example.com` | 只读契约、只对已运行目标发外部 HTTP，不读源码、不生成补丁 |

## 漏洞支持矩阵

「静态线索」= 能从源码定位候选；「动态取证」= 能在真实运行实例上复现并交叉证明；「自动修复」= 能自动产出补丁并通过双重验收。

| 漏洞类别 | 静态线索 | 动态取证 | 自动修复 | 黑盒模式 |
| --- | --- | --- | --- | --- |
| 对象级越权（IDOR，路径参数 / 查询参数） | ✅ | ✅ 跨用户内容交叉证明（JSON 字段，或页面正文里本人独有的片段） | ✅ 确定性模板；编码代理可尝试 | ✅ |
| 无鉴权读取 / 纵向越权 | ✅ | ✅ 匿名读取内容证据；管理端点交叉证明 | 编码代理可尝试（无确定性模板） | ✅ |
| 路径穿越 | ✅ | ✅ 目标文件内容命中 | 编码代理可尝试（无确定性模板） | ✅ 明文 / 二次编码 |
| SQL 注入 | ✅ | ✅ 行数变化 / 数据库报错 / 数字语境三段差分 | 编码代理可尝试（无确定性模板） | ✅ 字符串 / 数字语境 |
| 命令注入 | ✅ | ✅ shell 展开令牌回显 | 编码代理可尝试（无确定性模板） | — |
| SSRF | ✅ | ✅ 本机一次性 canary 回连 | ❌ 只取证 + 人工修复指引 | ✅ 服务端真的回连才判漏洞 |
| 文件上传（主动内容） | ✅ | ✅ 同源回读 + 随机令牌 + 主动 Content-Type | ❌ 只取证 + 人工修复指引 | ✅ 需 `allowMutation` |
| JWT 伪造令牌 | ✅ | ✅ alg=none / 无效签名 / 源码密钥 + 身份回显 | ❌ 只取证 + 人工修复指引 | ✅ alg=none / 无效 HS256 + 身份回显 |
| 业务逻辑跳步 / 并发双花 | ✅ 语义动作白名单 | ✅ 状态回读 / 不同副作用标识 | ❌ 只取证 + 人工修复指引 | ✅ 跳步需 `allowMutation`，双花再加 `allowDestructive` |
| CORS 配置（反射 Origin + 允许凭证） | ❌ 无静态适配器 | ✅ 伪造 Origin 回显 + 允许凭证双证据 | ❌ 只取证 + 人工修复指引 | ✅ |
| CSRF（Cookie 会话跨站表单） | ❌ 无静态适配器 | ✅ 受害对象状态回读（仅 Cookie 会话 + `allowMutation`） | ❌ 只取证 + 人工修复指引 | ✅ 仅 Cookie 会话且显式开启写操作 |
| 反射型 XSS（HTML 上下文） | ❌ 无静态适配器 | ✅ 无害 canary 原样反射（`<gbx>` 不执行） | ❌ 只取证 + 人工修复指引 | ✅ |
| Supabase / PostgREST 暴露 | ✅ | ✅ 匿名直连返回数据行 | ❌ 平台策略，只给加固指引 | — |

补充口径：

- 「编码代理可尝试」= 本地交互模式开启 `llm.patch` 后，模型可提出补丁意图；补丁须逐条通过结构校验与双重验收才记 `verified`，否则回落 `vulnerable_unfixed`。**gate/CI 不启用编码代理。**
- 黑盒模式没有源码，因此所有类别都不产补丁；白盒中 SSRF / 上传 / JWT / 业务逻辑与竞态，以及 CORS / CSRF / 反射型 XSS 也**没有**确定性模板。
- CORS / CSRF / XSS 只做黑盒动态取证：CORS 只认「回显伪造 Origin + 允许凭证」，XSS 只认 HTML 响应里 canary 原样反射（不执行脚本），CSRF 只在 Cookie 会话且 `allowMutation` 开启时验证状态改写并尽力恢复；三者都不判定安全头缺失、SameSite 策略或存储型/DOM XSS。
- 黑盒里 SSRF / JWT / 上传 / 业务逻辑同样只认外部可观测证据：SSRF 只认「独立监听器收到带一次性令牌的回连」，JWT 只认「匿名被拒的端点用伪造令牌通过且响应回显伪造身份」（不猜密钥、不做字典），上传只认「同源回读命中同一随机令牌且内容类型可主动渲染」，业务逻辑只认「归属复读后状态真的变了」或「并发请求产生 ≥2 个不同副作用标识」。SSRF / JWT 无副作用默认执行，上传与状态跳步要 `allowMutation`，退款类双花还要 `allowDestructive`。
- 取不到内容级证据一律记 `inconclusive`，不计漏洞，也不计「已防住」。
- 页面型（SSR）目标的越权取证没有字段可比，改为「受害人本人会话页面里独有、且原样出现在这次响应正文里的内容片段」：片段由本人页面与攻击者自己页面两批正文相减得到（英文按词、中文按汉字二元组），要求**全部命中**才算证据。攻击者名下没有可比页面、或两页正文找不出独有片段时判 `inconclusive`，绝不把「页面结构相似」当成越权成功；未登录请求被重定向回登录表单算「拒绝」，不算正向断言回归。

## 技术栈支持矩阵

| 形态 | 白盒静态识别 | 白盒动态复现 | 黑盒 |
| --- | --- | --- | --- |
| Express / 手写路由 | ✅ | ✅ | ✅ |
| 传统服务端渲染（全站只有 HTML 页面，无 JSON 接口） | ✅（走手写路由识别） | ✅ 对象 ID 取自登录后页面链接，归属证据取自本人会话下的页面正文 | —（纯页面目标的黑盒发现未实测） |
| Next.js（App Router / Pages API） | ✅ | ✅ | ✅ |
| NestJS 装饰器路由 | ✅ | ✅ | ✅ |
| tRPC 过程 | ✅ | ✅（superjson / 裸 JSON 协商） | ✅ |
| GraphQL SDL | ✅ 字段级 | ✅ introspection 降级 | ✅ |
| Supabase / PostgREST | ✅ | ✅ | — |
| Python：FastAPI / Flask / Django + DRF | ✅ | ✅ | ✅ |
| Java / Spring Boot | ❌ 无适配器 | ❌ 启动器白名单不含 java/mvn/gradle | ✅ 仅黑盒（需自行启动目标） |
| Go / PHP / .NET / Ruby | ❌ | ❌ | ✅ 仅黑盒 |
| 无 HTTP 接口（脚本 / CLI / 离线工具） | ❌ | ❌ | ❌ |

黑盒模式不依赖源码形态：只要目标已运行、接口可经 HTTP 访问，就能做探测；路由发现依次尝试 OpenAPI（含 `swagger-config` 间接地址）、常见路径词表、前端模块图（静态/动态 import 递归）、构建清单（CRA/Vite）与 source map（`sourcesContent`），并接受同源绝对 URL 与无前缀业务资源字面量，**不在这些来源里的端点仍会漏**。

## 接入前提

- Node.js ≥ 22.5（`node:sqlite`）、Rust stable；桌面模式需 Tauri 2 平台依赖。
- 目标项目能按 `guardbuild.json` 启动（或自行启动后用黑盒 `--url`）。
- 跨用户越权需要 **≥2 个普通测试身份**，纵向越权需要管理身份。身份可以有两种来源：契约里直接给出已存在的账号口令；或**省略 `password`**，让引擎用目标自己的注册接口现建号（`register` 契约，口令随机生成、只进 Host 保险库，不落任何产物）。
- 空库沙箱不再要求人工准备数据。注册端点三层来源、逐层裁决：契约 `register.path` → 静态建号词表**唯一**命中 → **注册兜底代理**（`register.agent`，缺省跟随 `llm.enabled`，也可 `GUARDBUILD_LLM_SELFBOOT=1`）；第三层只是「模型在引擎给的 POST 编号菜单里挑一个端点并给字段名映射」，是否算数只由实跑决定（注册 2xx/409 → 新凭据真登上 → 会话回读），菜单里根本不含找回密码/重置一类端点，模型也改不了方法/URL/载荷。数据同理：`register.seed` 存在时按契约写（最多 8 步，`{canary}` 是本轮随机种子标识）；契约没写时走**观测选定**——引擎对候选写接口真写一条带标记的记录，再用回读通道复述，只有「本人看得到、其他非管理身份看不到」才算名下对象，`unattributed` / `absent` 的写入直接丢弃。任一环节不成立就判 `inconclusive`（exit 2，错误码 `identity_bootstrap_unavailable` / `identity_bootstrap_failed` / `identity_seed_failed` / `no_list_endpoint`），不会退回匿名探测再报「未发现漏洞」。纯黑盒目标（外部在跑的实例）一律不自举建号——那是对他人的写操作；CI gate 模式结构上不调用模型，只复用交互轮里已实测验证过的缓存提案并再复核一次。
- 运行期形态静态看不见时优先自动发现：响应包装与主键/归属字段、分页参数、多段路径参数取值都用两个测试身份的真实请求实测（结论见报告 `summary.resourceContract`）。自动发现试不出时再用契约显式声明：`responses.list/entity/id/owner`、`listEndpoint` + `query`、`routes` + `params`。声明或实测都缺时不会静默跳过，而是判 `inconclusive`（exit 2）。
- 建议用 `prepare` 步骤跑幂等种子脚本准备数据。
- 验证码 / MFA / SSO 需要先绕过或提供测试通道，当前不自动处理。

## 明确不支持

| 不支持项 | 现状 |
| --- | --- |
| Java / Spring Boot 白盒 | 静态没有 `.java` 解析、启动器白名单不含 java/mvn/gradle（最小权限设计） |
| OAuth 授权码 / 隐式 / 客户端凭据流程审计 | 不在覆盖内；JWT 只覆盖「伪造令牌放行」可实测子集 |
| 弱口令 / 密码字典 / 撞库 | 不做；JWT 只用源码里已写死的密钥，不猜密码 |
| 存储型 / DOM XSS 的浏览器执行验证 | 反射型只证明 canary 在 HTML 上下文未被转义；上传只证明主动内容可被同源取回——都不代替浏览器执行与存储链路验证 |
| 安全头缺失、依赖 CVE、反序列化 | 未覆盖；依赖 CVE 与「只报可复现证据」的定位冲突，最多进报告附录 |
| CSRF 的 SameSite / Token 语义判定 | 只证明跨站表单能改写已登录用户状态，不判定会话 Cookie 的 SameSite 属性 |
| 多步业务链、MFA/OTP/验证码、SSO | 未覆盖 |
| 子域名 / 端口 / 服务指纹、横向移动、批量导出 | 不做（产品红线） |
| 扫描任意线上生产系统 | 不做；外部目标须先授权，写操作默认关闭，远程仅 HTTPS 且主机需预声明 |
| 分布式锁正确性证明 | 竞态只证明「重复执行产生不同副作用」，不单独证伪锁实现 |

## 判定语义与退出码

| 退出码 | verdict | 含义 |
| --- | --- | --- |
| 0 | `no_candidates` / `not_reproducible` | 已扫描但无可探测候选，或攻击在真实实例上打不通——**不是执行失败，也不是「系统安全」的证明** |
| 1 | `vulnerable_unfixed` / `patchStatus=verified` / `verify_failed` | 漏洞证据成立（附补丁或人工修复指引） |
| 2 | `inconclusive`（`no_endpoints` / `attack_inconclusive` / `plan_incomplete` / `scout_routes_unverified` / `static_routes_unverified` / `no_list_endpoint` / `param_binding_unverified` / `blackbox_login_failed` / `no_attack_cases` / `identity_bootstrap_unavailable` / `identity_bootstrap_failed` / `identity_seed_failed`）/ `failed`（含 `login_form_rerendered` / `login_session_unverified`）/ `aborted` / `timeout` | 无法证明覆盖，或契约、环境、内部错误、超时、中断 |

- `no_candidates`（exit 0）：路由已识别，但没有候选同时命中「静态形状 + 攻击用例」，界面显示「已扫描 · 无安全候选」并列出支持清单。
- `not_reproducible`（exit 0）：静态有线索、攻击已发出但打不通，显示「已测未复现 · 未证明安全」。
- `inconclusive`（exit 2）：**没测到 ≠ 安全**。未识别到任何路由（`no_endpoints`）、静态分析给出的路由在真实实例上逐条打完全部不成立（`static_routes_unverified`，多见于挂载前缀/路径拼接类适配问题）、计划用例因身份 / 资源 / 运行期契约不足被跳过（`attack_inconclusive`）、候选端点缺少可寻址参数（`plan_incomplete`）、模型侦察给出的路由在真实运行实例上逐条打完全部不成立（`scout_routes_unverified`）、定位不到按归属过滤的列表接口（`no_list_endpoint`，两种实测事实分开写：静态与契约都没找到列表 / 列表接口存在但两个身份返回同一批对象即未按归属过滤）、多段路径参数取值来源实测不出（`param_binding_unverified`）、纯黑盒模式契约里配了账号但一个身份都登不上（`blackbox_login_failed`，身份族用例整族未执行）、登录与路由都正常却一个攻击用例都构造不出来（`no_attack_cases`，测试账号名下没有可读回的对象数据）都归这一档，门禁不放行，报告给出对应的契约补齐字段。
- `inconclusive` 中的身份自举四类（exit 2）：身份省略 `password` 由引擎随机生成、但注册端点三层来源都没落地（`identity_bootstrap_unavailable`；`static-ambiguous` 且兜底层未开启/无密钥/菜单里没有可选项时也归这里——引擎不猜，更不会对别人在跑的系统建号）、引擎用目标自己的注册接口建号或随后登录任一步未被真实接受（`identity_bootstrap_failed`）、号建了但按契约或观测都拿不到名下对象（`identity_seed_failed` / `no_list_endpoint`，没有归属对象就无从构造越权用例）。四类都不会退化成匿名探测后报「未发现漏洞」。边界要说清：模型可以**提议**注册端点与字段名映射，但「这个端点真的能建号、这对凭据真的能登上、这条数据真的只在本人列表里出现」全部由引擎实跑复核——口令生成、模板占位符校验、菜单策略线、canary 归因与终态判定都是确定性代码路径，模型的越界输出直接丢弃。
- `failed` 中的登录两类（exit 2）：目标把「密码错误」渲染成 HTTP 200 + 登录表单（`login_form_rerendered`），或状态码可接受、凭据也取到了，但拿静态分析已知的「无参数、只读、需登录」接口做鉴权回读时匿名与带会话的响应同形同码被拒（`login_session_unverified`）。两类都是**会话没建立**，若按状态码判定就会被记成登录成功、随后所有越权用例拿匿名会话打，产出假的「未复现」。分开登录入口的应用要用 `identities[].loginPath` 为每个身份指定端点；找不到可回读的探针接口时引擎不做判定，但会在报告里写明「会话真实性回读未执行」。

## 精度口径

- 基准语料：**14 个标注靶场**，逐靶场标注期望退出码、期望复现的攻击用例、期望静态候选（含一个「空库」靶场：库内没有账号，身份与数据由引擎自举后再打越权）。
- 黑盒基准语料：**25 个已运行靶场**，逐靶场标注期望退出码、期望/禁止出现的 vulnerable 用例族（写探测与 CSRF 开关分档，含 SSRF / 上传 / JWT / 业务逻辑的漏洞—默认关闭—加固三档对照，以及 robots/sitemap、Next `_buildManifest.js`、Swagger UI 内嵌地址三路发现各配一个加固对照）。
- 当前基线（2026-10-31 复跑，含自举靶场）：动态召回 **25/25**、误报 **0/25**、退出码一致 **14/14**、静态召回 **25/25**；黑盒用例召回 **46/46**、误报 **0/46**、退出码一致 **25/25**；均零模型调用（基准全部走 gate，自举兜底层在 gate 里结构性禁调用模型，所以这一口径没有因为新增 agent 层而松动）。
- 换场景演练（不进精度口径，进 CI 步骤）：`npm run e2e:selfboot-odd` **52 项断言 / 八轮**，靶场 `fixtures/selfboot-odd-shop` 故意用两个静态词表都打不中的命名（注册 `/api/huiyuan/add`、字段 `mail`/`pwd`、下单 `/api/xiadan`），并埋一个「回 201 但名下不落对象」的陷阱端点与一个策略禁止的找回密码端点。它锁住的是这套能力的边界而不只是成功率：agent 只被问一次就采纳、越界键全部丢弃、口令/模型原文/走私内容八轮零残留、关掉开关与没有密钥时 0 次外发并诚实 exit 2、列表未按归属过滤时报错写的是实测事实、gate 冷跑 0 调用、gate 复用已验证缓存并复核后仍复现。
- 第三方真实靶场层（可选，不进 CI）：`npm run benchmark:realworld` 打的是**上游真代码**（VulnAPI、OWASP Juice Shop），标注来自上游声明的漏洞清单 + 逐行核对源码。本机没这份代码就跳过，`--require=<id>` 才把跳过判失败。当前基线（2026-10-31 复跑，与 2026-10-25 结论一致）：**2/2 实跑、召回 3/3、明令禁止命中 0、未标注 0、退出码一致 2/2**；单轮约 6 分钟（VulnAPI 344.8s / Juice Shop 11.6s）。这一层的价值在于自建靶场给不出的东西：它实测暴露过一次误报——共享/全局集合（商品目录）两个身份都能看到同一批 id，被早先的版本读成「读到了别人的对象」；现在跨用户读写判定会先用攻击者自己的列表排除这种形状，回落为 `inconclusive`，并把它作为否定断言长期锁住。
- **这是「标注语料内」的召回率**，衡量已覆盖类别打得准不准，**不等于**被测项目没有漏洞。
- 静默成功型问题（不回显的盲注、带外 SSRF 等）按设计记 `inconclusive`：宁可不报，也不假报。

## 对外话术

### 可说

- 「对已知技术栈的 Web 项目做越权、注入、认证类漏洞的可复现门禁。」
- 「每条发现都有真实请求证据与复现步骤；修没修好由攻击复测和业务回归决定。」
- 「CI 门禁模式无人工交互、结构性禁止写回，退出码可直接决定 job 成败。」
- 「GitHub Actions 三平台自测矩阵持续运行（可给出 run id 与提交 SHA）。」
- 「已覆盖 10 类可复现漏洞、7 套白盒框架适配器；黑盒可覆盖任意已运行 HTTP 服务。」
- 「自动修复的确定性模板目前只覆盖 IDOR；其余类别在本地可尝试编码代理，CI 不启用。」

### 不可说（四项禁写）

1. **不写「CI 全平台绿灯」当作无条件结论**——必须附 run id + 提交 SHA，且说明只代表自测矩阵本身通过。
2. **不写「自动修复任意漏洞」或「AI 全自动修复」**——准确说法是「5 类候选可尝试生成补丁，须过严格校验与双重验收」。
3. **不写「支持任意框架」**——准确说法是「7 套白盒适配器；未知框架可选 LLM 侦察兜底；Java/Go/PHP/.NET/Ruby 仅黑盒」。
4. **不暗示可随意扫描真实生产系统**——写操作默认关闭、远程仅 HTTPS 且主机需预声明，对外测试以授权为前提。

### 常见问答

**问：能保证扫出所有漏洞吗？**
不能。它只对已覆盖的类别和形态给出「有证据」「已测未复现」两种诚实结论，测不到的部分单独记「无法证明」（exit 2）；「已测未复现」与「未命中」都不等于安全。

**问：为什么有些项目没有发现？**
先看终态：`no_candidates`（exit 0）表示已识别路由但无可探测候选；`not_reproducible`（exit 0）表示静态有线索但运行期打不通——两者都不是工具坏了，但也都**不等于安全**。若项目形态根本测不了（未识别到路由、用例因契约不足被跳过、多段路径没有参数来源），终态是 `inconclusive`（exit 2），门禁不放行；此时按报告建议补 `routes` / `openapi.file` / `identities` / `listEndpoint` / `responses` / `routes[].params` 后重跑。

**问：能直接改我的代码吗？**
默认不能。补丁只在临时 worktree 生成；写回需要用户在桌面端审阅 Diff 后授权，gate/CI 结构性禁止。

**问：能扫线上系统吗？**
只有在获得授权的测试环境。远程目标必须 HTTPS、主机需预声明；破坏性操作默认关闭，打开也需显式两级开关。

## 分发状态（实测）

`npm run app:dist` 已能产出自带运行时的 NSIS 安装器（2026-10-24 实测：`GuardBuild_0.1.0_x64-setup.exe`，29.4 MB，currentUser 安装、中英双语）。安装目录包含 `guardbuild.exe`、`guardbuild-headless.exe`、`runtime/node.exe`、`sidecar/`、`shared/`；实测在 PATH 中没有 node 的情况下，安装出来的 `guardbuild-headless --gate` 仍能完成取证（exit 1 + `vulnerable_unfixed` + 报告落盘）。`npm run e2e:package` 对同一布局做正负对照（移走 `runtime/node.exe` 必须 exit 2）。

仍有两个未闭环项：

1. **安装器未签名**：默认构建会触发 Windows SmartScreen；需配置 `GUARDBUILD_SIGN_CERT_THUMBPRINT` 或含 `%1` 的 `GUARDBUILD_SIGN_COMMAND` 后重新构建。
2. **没有自动更新通道**：升级需要重新分发安装器。

因此当前适合内部/可信任用户试用；面向陌生用户的正式发行版还需完成签名与更新通道。CI 场景使用无头宿主或 GitHub Action，不依赖桌面安装器。首次构建需要联网获取 Tauri 的 NSIS 工具链（缓存于 `%LOCALAPPDATA%\tauri\NSIS`），受限网络可预置该目录后离线构建。

## 维护约定

- 新增漏洞类别或框架适配器时，同步更新本文两张矩阵、`sidecar/lib/coverage.mjs`、README 与基准语料。
- 对外引用数字时写清「基准日期 + 语料规模 + 指标口径」。
- 本文与 `docs/project-experience.md` 冲突时，以本文与仓库代码为准。
