# 动作表规格（M1 第 4 项）

配套代码：`sidecar/lib/actiontable.mjs` · 单测：`sidecar/tests/action-table.test.mjs`

## 一、这张表是什么

**动作表 = 执行器（真正发请求的写死程序）物理上能做什么的唯一清单。** 配方是往这张表里填空：用哪个身份、什么方法、打到哪个槽位、带什么参数、放哪类载荷、要不要并发或先跳一步、打完从哪个通道回读。

三个角色不要混（详见 `agent-attack-loop-plan.md` 第三节）：

| 名字 | 谁能改 |
| --- | --- |
| 动作表 | **只随新工具注册而变长**，且注册要人批。自动环不许写（红线 1） |
| 配方 | 模型起草 → 校验器验填表 → 判卷器验能不能打中 → 用户批 |
| 判据 | 冻结。配方只能**引用名字**，不许内联 |

## 二、为什么必须「拒收」而不是「忽略」

Host 侧 `http.request` 的参数结构体没开 `deny_unknown_fields`，sidecar 也只是不读多余的键。也就是说：模型写 `cookieJar: true`，引擎**不会报错，只会当没看见**。

那正是本项目最恨的一类缺陷——「配方说打了，执行器没打」，最后报告里却留了一条绿。所以校验器的立场是：表外的动作、表外的参数，一律拒收，并逐条说清缺哪个动作。

这不是新发明，是同一立场的第三次落地：

- `sidecar/lib/execmenu.mjs` — 启动代理只能从菜单里挑编号，`cmd/args/shell/script` 等夹带字段直接丢弃
- `sidecar/lib/attackplan.mjs` — 攻击规划代理只能挑路由编号，`payload/body/headers/method/identity/verdict/severity` 等在 `SMUGGLED_KEYS` 里丢弃
- 本表 — 把「哪些字段是表内的」从散落的黑名单升级成一份可回读代码的清单

## 三、表的结构

| 表 | 内容 | 锚点（真实实现） |
| --- | --- | --- |
| `ACTIONS` | 15 条动作，每条带 `params` / `required` / `limits` / `anchor` | `probe.mjs` 各族用例、`host.rs` 的 `http.request`、`http-follow.mjs`、`graphqlwire.mjs`、`main.mjs` 的写/删开关 |
| `SLOTS` | 目标位置只能引用探测计划里真存在的 13 个槽位 | `planner.mjs` 的 `planView` |
| `METHODS` | `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS` | `host.rs` 里 `CONNECT/TRACE` 硬拒、请求体 >256KB 硬拒 |
| `VERDICT_RULES` | 5 条已注册判据（`attack-repro` / `cross-proof` / `target-touched` / `business-regress` / `inconclusive`） | `probe.mjs` 的 `verifyAttack` / `crossProof` / `assertTargetTouched`、`shared/protocol.mjs` |
| `KNOWN_IMPOSSIBLE` | 常见但**永远做不了**的写法（Cookie 容器、代理、客户端证书、流式、自动重试、WebSocket、带外信道），每条带一句为什么 | — |

物理上做不到的几处，写在这里是为了口径明确：没有 Cookie 容器（会话凭据只由 Host 保险库按身份名注入）；重定向只跟同源、只跟 GET 或 307/308、最多 2 跳；并发只有 `request.concurrent` 一条道（用例默认串行，否则「第几次打到」不可重放）；没有带外信道，SSRF 只打本机 canary。

## 四、拒收规则

| 规则 | 拒收什么 | 背后是哪条线 |
| --- | --- | --- |
| `action_out_of_table` | 动作名不在表内 | 假绿灯（说了没做） |
| `param_out_of_table` | 动作名对，但挂了该动作不读的键 | 同上 |
| `missing_required` / `bad_step` / `missing_id` / `duplicate_id` / `bad_reference` | 表本身不可重放 | 红线 2：判定用的请求序列必须可重放 |
| `method_denied` / `method_unknown` / `over_limit` | 越过程序写死的边界 | 执行器真会拒，别让配方以为能过 |
| `bad_identity` | 身份位写了凭据值（`Bearer…` / `eyJ…` / 长 base64） | 红线 6：凭据值不落任何渠道 |
| `slot_unknown` / `bad_path` | 指向不存在的槽位或非法路径 | 引用不存在的目标 = 空打 |
| `verdict_unknown` / `verdict_inline` | 引用不存在的判据，或把判定逻辑写进配方 | 红线 1 + 红线 4：结论只能由判卷代码落笔 |
| `gate_flip` | 配方根上带 `allowMutation` / `allowDestructive` / `forceAllow` / `skipGate` | 红线 1：写/删探测的默认开关冻结 |
| `gate_unknown` / `enum_value` | 声明的开关名不存在（步骤上的 `gate`、或 `gate.mutation` 的 `kind`） | 冻结项只能引用真开关，不许自造一个「alwaysOn」 |
| `bad_version` / `empty_steps` / `not_object` | 不是一张表 | — |

凭据这一条还有个容易漏的点：拒收文案会把「给了什么」回显出来给人读，而它自己也要进事件流和报告。所以 `identity` / `body` / `content` / `claims` 这类位置的值**先换成 `<已隐去 · N 字符>` 再回显**，任何位置的值只要长得像凭据也一样处理。单测里塞了一条真 JWT 形状的值，断言它不出现在拒收结果里。

## 五、拒收输出长什么样

`formatRejections` 的原文（一张手造的坏配方：表外动作 + 夹带重试 + 内联判据）：

```
配方被拒收：3 处表外或冻结冲突
- steps[0]#s1.action：动作表里没有这一项，执行器不会去做它（给了 "concurrent.request"） → 缺的动作：concurrent.request（表内最近的是 request.concurrent） → 应走能力请求单，不是改配方措辞绕过
- steps[1]#s2.retry：无自动重试（重试会让「第几次打到」不可重放）（给了 "retry"） → 缺的动作：request.as.retry
- verdict.vulnerableIf：判据不许内联：结论只能由判卷代码落笔，配方只能引用名字（给了 "vulnerableIf"）
```

每条拒收都带 `{ missingAction, nearest, needCapabilityRequest, allowed }`。`needCapabilityRequest=true` 表示「这不是写错了，是引擎真没有这个器官」，它就是第 9 项能力请求单的输入；已知做不到的（`KNOWN_IMPOSSIBLE`）不生成请求单，防止有人拿它反复申请带外信道。
`nearest` 只是提示，且要求至少一段完全对得上才给——对不上的硬凑会把人引向另一条错动作。

## 六、表不许脱离实现

每条动作与判据都带 `anchor: {file, token}`，`checkAnchors(repoRoot)` 逐条回读代码，单测断言全部可解析。

作用是：将来删掉某个执行分支却忘了删表，测试就红。**表上写着能做、代码里已经做不到**，比表短更危险——它会让配方写出一个「校验通过但什么都没发生」的攻击步骤。

## 七、校验器的权限边界

`validateRecipe` 只否决，不给通过背书。`ok: true` 的全文含义是「这张表没填错」，**不包含**「这条配方打得中漏洞」。后者是第 6 项判卷器拿考卷（漏洞版 / 加固版 / 干净对照）验出来的。

按红线 3 的同一口径：能写「退回」的角色很多，能写「通过」的只有判卷器。
