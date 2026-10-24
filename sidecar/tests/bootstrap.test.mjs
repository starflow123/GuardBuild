/**
 * 有界启动代理（S3-full）：模型逐步选动作，引擎逐步实跑。
 * 这里断言的是边界——只按菜单编号执行、成功只由真实拉起判定、预算一到就诚实收手、
 * 审计与事件里不落模型原文；不是断言「模型更会修项目」。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { bootstrapEnabled, runBootstrapAgent } from "../lib/bootstrap.mjs";
import { normalizeBootstrap } from "../lib/targetconfig.mjs";

const LEAK = "SECRET-CMDLINE-SHOULD-NOT-BE-STORED";

function fakeCtx(over = {}) {
  const calls = [];
  const events = [];
  const actions = [];
  const ctx = {
    sessionId: "s-1",
    projectRoot: "D:\\demo",
    gate: false,
    state: "probing",
    tokens: { project: "tok-project", spawn: "tok-spawn" },
    targetConfig: { bootstrap: { maxSteps: 6 } },
    calls,
    rpc: {
      async request(method, params) {
        calls.push({ method, params });
        if (method === RPC_TO_HOST.FS_READ) return { content: '{"scripts":{"build":"tsc"}}' };
        if (method === RPC_TO_HOST.FS_LIST) return { entries: [{ path: "D:\\demo\\src\\a.js", kind: "file" }] };
        if (method === RPC_TO_HOST.PROC_SPAWN) return { pid: 42 };
        if (method === RPC_TO_HOST.PROC_WAIT_EXIT) return { exited: true, exitCode: 0 };
        if (method === RPC_TO_HOST.PROC_LOGS) return { lines: [{ line: "install ok" }] };
        if (method === RPC_TO_HOST.PROC_KILL) return { killed: true };
        throw new Error(`未预期的 RPC：${method}`);
      },
    },
    emit: (ev) => events.push(ev),
    db: { insertAgentAction: (a) => actions.push(a) },
    ...over,
  };
  return { ctx, calls, events, actions };
}

const MANIFESTS = [
  { rel: "package.json", content: JSON.stringify({ scripts: { build: "tsc -b" } }) },
  { rel: "package-lock.json", content: "{}" },
];

const STARTS = [{ cmd: "npm", args: ["run", "start"], cwd: ".", source: "scout" }];

/** 按顺序回放模型的选择；每条都故意带上自己的命令行，看引擎是否照收 */
function scripter(picks) {
  let i = 0;
  const prompts = [];
  return {
    prompts,
    chatImpl: async (_ctx, opts) => {
      prompts.push(opts.userPrompt);
      const pick = picks[Math.min(i, picks.length - 1)];
      i += 1;
      return { content: JSON.stringify(pick), model: "deepseek-chat" };
    },
  };
}

test("开关：gate 结构性禁用，配置显式优先于环境变量", () => {
  const saved = process.env.GUARDBUILD_LLM_BOOTSTRAP;
  try {
    process.env.GUARDBUILD_LLM_BOOTSTRAP = "1";
    assert.equal(bootstrapEnabled({ gate: true, targetConfig: { bootstrap: { enabled: true } } }), false);
    assert.equal(bootstrapEnabled({ gate: false, targetConfig: { bootstrap: { enabled: true } } }), true);
    assert.equal(bootstrapEnabled({ gate: false, targetConfig: { bootstrap: { enabled: false } } }), false);
    assert.equal(bootstrapEnabled({ gate: false, targetConfig: {} }), true, "env 打开时默认启用");
    delete process.env.GUARDBUILD_LLM_BOOTSTRAP;
    assert.equal(bootstrapEnabled({ gate: false, targetConfig: {} }), false, "默认关闭，必须显式开启");
  } finally {
    if (saved === undefined) delete process.env.GUARDBUILD_LLM_BOOTSTRAP;
    else process.env.GUARDBUILD_LLM_BOOTSTRAP = saved;
  }
});

test("闭环：读一次、装一次、启动候选真实就绪才算成功", async () => {
  const { ctx, calls, events, actions } = fakeCtx();
  const sc = scripter([
    { action: "read", path: "src/a.js", cmd: LEAK },
    { action: "exec", id: 1 },
    { action: "start", candidate: 1 },
  ]);
  let started = 0;
  const summary = await runBootstrapAgent(ctx, {
    reason: "target_not_ready: 端口未监听",
    starts: STARTS,
    getToken: async () => "tok-net",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async (entry) => {
      started += 1;
      assert.equal(entry.shape, "npm run start");
      return { ok: true, target: { url: "http://127.0.0.1:3000", pid: 99 }, start: { cmd: "npm", args: ["run", "start"] } };
    },
  });

  assert.equal(summary.outcome, "started");
  assert.equal(summary.stepsUsed, 3);
  assert.equal(summary.rejected, 0);
  assert.equal(started, 1, "只真实拉起一次");
  assert.deepEqual(summary.start.args, ["run", "start"]);
  assert.equal(summary.url, "http://127.0.0.1:3000");
  assert.ok(summary.remainingMs < 480_000, "剩余预算随时间收敛");

  const reads = calls.filter((c) => c.method === RPC_TO_HOST.FS_READ);
  assert.ok(reads.every((c) => c.params.token === "tok-project" && c.params.redact === true), "只读走 project 令牌并脱敏");
  assert.deepEqual(reads.map((c) => c.params.path), ["D:\\demo/src/a.js"]);
  const spawn = calls.find((c) => c.method === RPC_TO_HOST.PROC_SPAWN);
  assert.deepEqual(spawn.params.args, ["ci"], "执行菜单里的 npm ci，不是模型带的命令");
  assert.equal(spawn.params.token, "tok-spawn");
  assert.equal(spawn.params.role, "bootstrap");
  assert.deepEqual(
    actions.map((a) => a.action),
    ["sanitize", "read", "exec", "start"],
    "第一步就把「模型自带命令字段被丢弃」记在审计里"
  );
  assert.deepEqual(
    events.map((e) => e.kind),
    ["bootstrap", "bootstrap", "bootstrap", "bootstrap"]
  );
  assert.equal(events.every((e) => e.phase === "probing"), true);
});

test("模型想自己拼命令行：字段丢弃并留痕，实际执行仍是菜单里那条", async () => {
  const { ctx, calls, actions } = fakeCtx();
  const sc = scripter([
    { action: "exec", id: 2, cmd: "node", args: [LEAK], shell: "/bin/sh" },
    { action: "giveup", note: "到此为止" },
  ]);
  let tried = 0;
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => {
      tried += 1;
      return { ok: true, target: { url: "x" } };
    },
  });
  const spawn = calls.find((c) => c.method === RPC_TO_HOST.PROC_SPAWN);
  assert.deepEqual([spawn.params.cmd, ...spawn.params.args], ["npm", "run", "build"], "id 2 是 npm run build");
  assert.equal(actions[0].action, "sanitize");
  assert.equal(actions[0].subject, "cmd,args,shell");
  assert.equal(actions[1].subject, "npm run build");
  assert.equal(tried, 0, "没有实跑就绪，就不会有 started");
  assert.equal(summary.outcome, "gave_up");
  assert.equal(actions.some((a) => JSON.stringify(a).includes(LEAK)), false, "模型原文不进审计");
});

test("非法编号被拒并回喂原因，且不执行任何进程", async () => {
  const { ctx, calls, events } = fakeCtx();
  const sc = scripter([{ action: "exec", id: 99 }, { action: "giveup", note: "缺外部数据库" }]);
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => ({ ok: true, target: { url: "x" } }),
  });
  assert.equal(summary.rejected, 1);
  assert.equal(summary.outcome, "gave_up");
  assert.equal(calls.some((c) => c.method === RPC_TO_HOST.PROC_SPAWN), false);
  assert.match(events[0].data.note, /不在菜单内/);
  assert.ok(sc.prompts[1].includes("上一步选择被拒"), "拒绝原因回喂，模型知道别 repeats");
});

test("重复动作短路：同一条 exec 不会二次实跑", async () => {
  const { ctx, calls } = fakeCtx();
  const sc = scripter([
    { action: "exec", id: 1 },
    { action: "exec", id: 1 },
    { action: "giveup", note: "重复无意义" },
  ]);
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => ({ ok: false, error: "未就绪" }),
  });
  assert.equal(calls.filter((c) => c.method === RPC_TO_HOST.PROC_SPAWN).length, 1, "第二次只短路");
  assert.equal(summary.outcome, "gave_up");
  assert.ok(sc.prompts[2].includes("已经执行过"), sc.prompts[2].slice(0, 200));
});

test("构建成功后允许重试启动：去重不把「状态已改变」一起否掉", async () => {
  const { ctx, calls } = fakeCtx();
  const sc = scripter([
    { action: "start", candidate: 1 },
    { action: "exec", id: 2 },
    { action: "start", candidate: 1 },
  ]);
  let tried = 0;
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => {
      const n = (tried += 1);
      return n === 1 ? { ok: false, error: "缺少构建产物" } : { ok: true, target: { url: "http://127.0.0.1:3000" } };
    },
  });
  assert.equal(tried, 2, "构建后重试应当真实拉起，而不是被去重短路");
  assert.equal(calls.filter((c) => c.method === RPC_TO_HOST.PROC_SPAWN).length, 1, "构建只跑一次");
  assert.equal(summary.outcome, "started");
  assert.equal(summary.url, "http://127.0.0.1:3000");
});

test("重试有上限：没有新的成功 exec 时仍短路，最多实跑 2 次", async () => {
  const { ctx } = fakeCtx({ targetConfig: { bootstrap: { maxSteps: 5 } } });
  const sc = scripter([
    { action: "start", candidate: 1 },
    { action: "start", candidate: 1 },
    { action: "exec", id: 1 },
    { action: "start", candidate: 1 },
    { action: "start", candidate: 1 },
  ]);
  let tried = 0;
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => {
      tried += 1;
      return { ok: false, error: "未就绪" };
    },
  });
  assert.equal(tried, 2, "第 2 次无状态变化被短路，第 4 次是重试，第 5 次到达上限");
  assert.equal(summary.outcome, "budget_exhausted");
  const shorted = summary.actions.filter((a) => a.note === "重复动作短路");
  assert.equal(shorted.length, 2);
  assert.ok(sc.prompts[2].includes("没有成功的安装/构建"), sc.prompts[2].slice(0, 300));
});

test("预算：步数上限到点收手，状态是 budget_exhausted 而不是成功", async () => {
  const { ctx } = fakeCtx({ targetConfig: { bootstrap: { maxSteps: 2 } } });
  const sc = scripter([{ action: "read", path: "a.js" }]);
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => ({ ok: true, target: { url: "x" } }),
  });
  assert.equal(summary.stepsUsed, 2);
  assert.equal(summary.outcome, "budget_exhausted");
  assert.match(summary.budgetStop, /步数上限/);
  assert.equal(sc.prompts.length, 2, "超限后不再问模型");
});

test("预算：输出字符预算同样能收手", async () => {
  const { ctx } = fakeCtx({
    targetConfig: { bootstrap: { maxOutputChars: 5_000 } },
    rpc: {
      async request() {
        return { content: "x".repeat(3_000) };
      },
    },
  });
  const sc = scripter([{ action: "read", path: "a.js" }]);
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => ({ ok: true, target: { url: "x" } }),
  });
  assert.equal(summary.outcome, "budget_exhausted");
  assert.match(summary.budgetStop, /累计输出预算/);
  assert.ok(summary.usedOutputChars >= 5_000 - 1_200, `已计 ${summary.usedOutputChars}`);
});

test("启动候选失败：代理不自评成功，把日志尾部回喂模型", async () => {
  const { ctx, actions } = fakeCtx();
  const sc = scripter([
    { action: "start", candidate: 1 },
    { action: "giveup", note: "缺数据库连接串" },
  ]);
  const err = Object.assign(new Error("就绪超时"), {
    code: "target_not_ready",
    hint: "检查监听端口",
    output: ["TypeError: Cannot read config", `env ${LEAK} missing`],
  });
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: sc.chatImpl,
    tryStart: async () => {
      throw err;
    },
  });
  assert.equal(summary.outcome, "gave_up");
  assert.equal(actions.find((a) => a.action === "start").ok, false);
  assert.ok(sc.prompts[1].includes("就绪超时"), "真实失败原因进了观察");
});

test("LLM 不可用：如实标记 llm_unavailable，不猜动作也不报错中断", async () => {
  const { ctx, events } = fakeCtx();
  const summary = await runBootstrapAgent(ctx, {
    starts: STARTS,
    getToken: async () => "t",
    readManifestsImpl: async () => MANIFESTS,
    chatImpl: async () => {
      throw new Error("DeepSeek API 返回 HTTP 402");
    },
    tryStart: async () => ({ ok: true, target: { url: "x" } }),
  });
  assert.equal(summary.outcome, "agent_error");
  assert.match(summary.error, /HTTP 402/);
  assert.equal(events.at(-1).data.action, "ask");
});

test("清单读取：只用 project 令牌、走脱敏，读不到的清单直接跳过", async () => {
  const reads = [];
  const { ctx } = fakeCtx({
    rpc: {
      async request(method, params) {
        reads.push({ method, path: params.path, token: params.token, redact: params.redact });
        if (params.path.endsWith("package.json")) return { content: '{"scripts":{"build":"tsc"}}' };
        throw new Error("宿主拒绝：文件不存在");
      },
    },
  });
  const sc = scripter([{ action: "giveup", note: "没有可安装项" }]);
  const summary = await runBootstrapAgent(ctx, {
    starts: [],
    getToken: async () => "t",
    chatImpl: sc.chatImpl,
    tryStart: async () => ({ ok: false }),
  });
  assert.equal(summary.outcome, "gave_up");
  assert.equal(reads.every((c) => c.method === RPC_TO_HOST.FS_READ && c.token === "tok-project" && c.redact === true), true);
  assert.equal(reads.length, 9, "只试固定清单文件名，不做目录遍历");
  assert.deepEqual(
    reads.map((c) => c.path.split("/").pop()),
    [
      "package.json",
      "package-lock.json",
      "npm-shrinkwrap.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "requirements.txt",
      "pyproject.toml",
      "uv.lock",
      "Procfile",
    ]
  );
  assert.ok(reads.some((c) => c.path.endsWith("package.json")));
  assert.equal(reads.some((c) => c.path.endsWith(".env")), false, "清单白名单里没有密钥文件");
});

test("契约 bootstrap 字段：预算可收紧，不可放宽到失控", () => {
  const d = normalizeBootstrap({});
  assert.equal(d.maxSteps, 6);
  assert.equal(d.stepTimeoutMs, 120_000);
  assert.equal(d.totalBudgetMs, 480_000);
  assert.equal(d.maxOutputChars, 60_000);
  assert.equal(d.enabled, undefined, "缺省由环境变量决定");

  const clamped = normalizeBootstrap({ maxSteps: 999, stepTimeoutMs: 1, totalBudgetMs: 1, maxOutputChars: 1 });
  assert.equal(clamped.maxSteps, 10);
  assert.equal(clamped.stepTimeoutMs, 5_000);
  assert.equal(clamped.totalBudgetMs, 30_000);
  assert.equal(clamped.maxOutputChars, 5_000);

  assert.equal(normalizeBootstrap({ enabled: true }).enabled, true);
  assert.equal(normalizeBootstrap({ enabled: "yes" }).enabled, undefined, "非布尔不认，避免字符串开关");
  assert.equal(normalizeBootstrap("nope"), null);
});
