/**
 * Supabase 适配器单元测试：静态检测纯函数与环境解析 / JWT 解码。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  parseEnvContent,
  decodeJwtPayload,
  jwtRole,
  detectSupabaseStatic,
  isLoopbackHostname,
} from "../lib/supabase.mjs";

/** 构造一个可被 jwtRole 识别角色的测试 JWT（header.payload.sig，均为 base64url） */
function mkJwt(payloadObj, sig = "SIGVALUE123") {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payloadObj)}.${sig}`;
}

const ANON_JWT = mkJwt({ role: "anon", iss: "supabase" });
const SERVICE_JWT = mkJwt({ role: "service_role", iss: "supabase" });

test("parseEnvContent: 解析键值 / 去注释 / 去引号 / 忽略空值", () => {
  const m = parseEnvContent(
    [
      "# comment line",
      "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co",
      'SUPABASE_ANON_KEY="quoted value"',
      "EMPTY_ONE=",
      "export SPACE_KEY = spaced",
      "  ",
    ].join("\n")
  );
  assert.equal(m.get("NEXT_PUBLIC_SUPABASE_URL"), "https://abc.supabase.co");
  assert.equal(m.get("SUPABASE_ANON_KEY"), "quoted value");
  assert.equal(m.has("EMPTY_ONE"), false, "空值应被忽略");
  assert.equal(m.get("SPACE_KEY"), "spaced");
});

test("jwtRole: 解码载荷中的 role 字段", () => {
  assert.equal(jwtRole(ANON_JWT), "anon");
  assert.equal(jwtRole(SERVICE_JWT), "service_role");
  assert.equal(jwtRole("not-a-jwt"), null);
  assert.equal(decodeJwtPayload(null), null);
});

test("isLoopbackHostname: 仅本机回环主机为真", () => {
  assert.equal(isLoopbackHostname("127.0.0.1"), true);
  assert.equal(isLoopbackHostname("localhost"), true);
  assert.equal(isLoopbackHostname("::1"), true);
  assert.equal(isLoopbackHostname("abc.supabase.co"), false);
});

test("detectSupabaseStatic: 从 createClient 环境变量引用 + .from 表名提取", () => {
  const files = [
    {
      path: "src/client.js",
      content:
        `import { createClient } from '@supabase/supabase-js'\n` +
        `const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)\n` +
        `const { data } = await supabase.from('profiles').select('*')\n` +
        `supabase.from('orders').select('*')`,
    },
  ];
  const envVars = new Map([
    ["NEXT_PUBLIC_SUPABASE_URL", "https://abc.supabase.co"],
    ["NEXT_PUBLIC_SUPABASE_ANON_KEY", ANON_JWT],
  ]);
  const r = detectSupabaseStatic({ files, envVars, envFileNames: [".env"], overrides: {} });
  assert.equal(r.detected, true);
  assert.equal(r.url, "https://abc.supabase.co");
  assert.equal(r.anonKey, ANON_JWT);
  assert.equal(r.keyRole, "anon");
  assert.deepEqual(r.tables.map((t) => t.name).sort(), ["orders", "profiles"]);
  assert.equal(r.serviceRoleLeak, null);
  assert.equal(r.probeable, true);
});

test("detectSupabaseStatic: 字面量 URL 与硬编码 service_role 判定为客户端泄露", () => {
  const files = [
    {
      path: "lib/sb.js",
      content:
        `const sb = createClient("https://demo.supabase.co", "${ANON_JWT}")\n` +
        `sb.from('users').select('*')`,
    },
    {
      path: "lib/leak.js",
      content:
        `import { createClient } from '@supabase/supabase-js'\n` +
        `const adminKey = "${SERVICE_JWT}"; // 危险：service_role 直接写进前端源码`,
    },
  ];
  const r = detectSupabaseStatic({ files, envVars: new Map(), envFileNames: [], overrides: {} });
  assert.equal(r.detected, true);
  assert.equal(r.url, "https://demo.supabase.co");
  assert.equal(r.anonKey, ANON_JWT);
  assert.equal(r.serviceRoleLeak?.source, "hardcoded-literal");
  assert.equal(r.serviceRoleLeak?.file, "lib/leak.js");
});

test("detectSupabaseStatic: service_role 环境变量仅在客户端前缀下才算泄露", () => {
  const envVars = new Map([
    ["SUPABASE_SERVICE_ROLE_KEY", SERVICE_JWT], // 服务端专用，正常
    ["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", SERVICE_JWT], // 客户端前缀 = 泄露
  ]);
  const r = detectSupabaseStatic({
    files: [],
    envVars,
    envFileNames: [".env"],
    overrides: { url: "https://x.supabase.co", anonKey: ANON_JWT },
  });
  assert.equal(r.detected, true, "url+anonKey 亦可判定 detected");
  assert.equal(r.serviceRoleLeak?.source, "env-client-prefix");
  assert.equal(r.serviceRoleLeak?.name, "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY");
  const flags = Object.fromEntries(r.serviceRoleEnvs.map((e) => [e.name, e.clientExposed]));
  assert.equal(flags["SUPABASE_SERVICE_ROLE_KEY"], false);
  assert.equal(flags["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"], true);
});

test("detectSupabaseStatic: 仅服务端 service_role（无客户端前缀）不构成泄露", () => {
  const envVars = new Map([["SUPABASE_SERVICE_ROLE_KEY", SERVICE_JWT]]);
  const r = detectSupabaseStatic({
    files: [],
    envVars,
    envFileNames: [".env"],
    overrides: { url: "https://x.supabase.co", anonKey: ANON_JWT },
  });
  assert.equal(r.serviceRoleLeak, null);
});

test("detectSupabaseStatic: 占位符 key 被过滤，导致不可探测", () => {
  const files = [{ path: "a.js", content: `createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY); sb.from('t')` }];
  const envVars = new Map([
    ["SUPABASE_URL", "https://abc.supabase.co"],
    ["SUPABASE_KEY", "your-anon-key-here"],
  ]);
  const r = detectSupabaseStatic({ files, envVars, envFileNames: [".env"], overrides: {} });
  assert.equal(r.anonKey, null, "占位值应被忽略");
  assert.equal(r.probeable, false);
});

test("detectSupabaseStatic: overrides.tables 追加静态未发现但契约声明的表", () => {
  const r = detectSupabaseStatic({
    files: [],
    envVars: new Map(),
    envFileNames: [],
    overrides: { url: "https://x.supabase.co", anonKey: ANON_JWT, tables: ["messages", "非法 名"] },
  });
  assert.deepEqual(r.tables.map((t) => t.name), ["messages"], "非法表名被拒绝");
  assert.equal(r.probeable, true);
});

test("detectSupabaseStatic: 非 Supabase 项目不误报", () => {
  const files = [{ path: "server.js", content: `app.get('/api/orders/:id', handler)` }];
  const r = detectSupabaseStatic({ files, envVars: new Map(), envFileNames: [], overrides: {} });
  assert.equal(r.detected, false);
  assert.equal(r.probeable, false);
});
