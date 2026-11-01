/**
 * 判卷器（方案第 6 项）：拿考卷验一份配方的写死程序。四道闸——
 *   G1 hit            漏洞版必须打中
 *   G2 hardened_zero  加固版必须一条不报
 *   G3 clean_control  干净对照不许凭空造漏洞
 *   G4 consistent     连跑两次结论一致
 *
 * 这一层**不碰进程、不读文件、不调模型**：实跑由 driver 做完，把每次的观察喂进来。
 * 判据（哪条算打中、哪样算误报）写死在这里，考卷与配方都改不动它——它是冻结资产（红线 1、4）。
 *
 * 少一次跑 = `not_graded`，整份考卷判不通过；「没考」永远不等于「考过了」。
 */
export const GRADE_VERSION = "gb-grade-1";
export const GATES = ["hit", "hardened_zero", "clean_control", "consistent"];
export const VARIANTS = ["vulnerable", "hardened", "clean"];

const NOT_GRADED = "not_graded";

function gate(ok, status, detail) {
  const passed = ok === true;
  // status 由调用方给：没跑成的闸要落 not_graded / invalid_exam，不能统一压成 failed
  return { ok: passed, status: passed ? "passed" : status ?? "failed", ...(detail ? { detail } : {}) };
}

/** 一次观察算不算「真的跑完并留下了可核对的证据」：崩溃/超时/没有 report 都不算 */
function isUsable(run) {
  return !run?.timedOut && !run?.error && run?.reportPresent === true;
}

function verdictMap(run) {
  return Object.fromEntries(Object.entries(run?.caseVerdicts ?? {}).sort(([a], [b]) => (a < b ? -1 : 1)));
}

/** 同一变体连跑两次的结论必须逐条相等：用例判定与退出码都算结论 */
function compareRuns(a, b) {
  const diffs = [];
  const va = verdictMap(a);
  const vb = verdictMap(b);
  for (const id of new Set([...Object.keys(va), ...Object.keys(vb)])) {
    if (va[id] !== vb[id]) diffs.push(`${id}: ${va[id] ?? "无记录"} vs ${vb[id] ?? "无记录"}`);
  }
  if (a?.exit !== b?.exit) diffs.push(`退出码: ${a?.exit ?? "—"} vs ${b?.exit ?? "—"}`);
  return diffs;
}

function vulnerableIds(run) {
  return new Set(run?.vulnerableCaseIds ?? []);
}

/**
 * 一次跑的「生命体征」：哪些攻击用例真的落地了、哪些业务用例通过了、哪些业务回退了。
 * 零报本身不是证据——必须先确认这一轮靶子是活的、引擎确实在打，才谈得上「加固版不报」。
 */
function lifeSigns(run) {
  const verdicts = run?.caseVerdicts ?? {};
  const attackLanded = [];
  const businessPassed = [];
  const regressed = [];
  for (const [id, verdict] of Object.entries(verdicts)) {
    if (!verdict) continue;
    if (id.startsWith("attack-")) attackLanded.push(id);
    else if (id.startsWith("business-") && verdict === "passed") businessPassed.push(id);
    if (verdict === "regressed" && id.startsWith("business-")) regressed.push(id);
  }
  return { attackLanded: attackLanded.length, attackIds: attackLanded, businessPassed, regressed };
}

/**
 * @param {object} p.exam loadExams() 归一化后的考卷
 * @param {string[]} p.recipeCaseIds 该配方能产出的全部用例编号（加固版拿它判「这一族一条都不许报」）
 * @param {Array} p.runs 每次实跑的观察：{variant, attempt, exit, outcome, vulnerableCaseIds, caseVerdicts, reportPresent, timedOut, error}
 * @param {string} [p.examInvalid] driver 派生加固版失败时传入：考卷本身无效，四道闸一条都不算过
 */
export function gradeExam({ exam, recipeCaseIds = [], runs = [], examInvalid = null }) {
  const examId = exam?.examId ?? "(无考卷)";
  if (examInvalid) {
    return {
      version: GRADE_VERSION,
      examId,
      recipe: exam?.recipe ?? null,
      family: exam?.family ?? null,
      graded: false,
      pass: false,
      examInvalid: String(examInvalid),
      gates: Object.fromEntries(GATES.map((g) => [g, gate(false, "invalid_exam", "考卷无效，这道闸没有跑")])),
      reasons: [`考卷无效：${examInvalid}`],
    };
  }

  const expect = exam?.vulnerable?.expect ?? [];
  // 加固版只考这一族：靶子里别的族仍是漏洞（考卷只补了一处补丁），报它们不算失败
  const familyCaseIds = [...new Set([...(recipeCaseIds ?? []), ...expect])];
  const repeat = exam?.repeat ?? 2;
  const reasons = [];

  const usable = new Map();
  const unusable = new Map();
  for (const v of VARIANTS) {
    const list = runs.filter((r) => r?.variant === v).sort((a, b) => (a.attempt ?? 0) - (b.attempt ?? 0));
    usable.set(v, list.filter(isUsable));
    unusable.set(v, list.filter((r) => !isUsable(r)));
  }

  const missing = VARIANTS.filter((v) => runs.some((r) => r?.variant === v) && usable.get(v).length === 0);
  const shortRuns = VARIANTS.filter((v) => usable.get(v).length > 0 && usable.get(v).length < repeat);
  const neverRan = VARIANTS.filter((v) => !runs.some((r) => r?.variant === v));

  const noRunReason = (v) =>
    unusable.get(v).length
      ? `G·${v} 没有一次可用实跑（超时/崩溃/没产出 report：${unusable.get(v).map((r) => r.error ?? `退出码 ${r.exit}`).join("；")}）`
      : `G·${v} 根本没有实跑`;

  // —— G1 漏洞版必须打中（每次可用跑都要打满） ——
  const vulnRuns = usable.get("vulnerable");
  let hit = null;
  if (!vulnRuns.length) reasons.push(noRunReason("vulnerable"));
  else {
    const missed = [...new Set(vulnRuns.flatMap((r) => expect.filter((id) => !vulnerableIds(r).has(id))))];
    hit = gate(missed.length === 0, missed.length ? "failed" : NOT_GRADED, missed.length ? { missed } : undefined);
    if (!hit.ok) reasons.push(`G1 漏洞版没打中：${missed.join(", ")}`);
  }

  // —— G2 加固版必须一条不报 ——
  // 「没报」有三种来源，只有一种算证据：靶子是活的、引擎仍在打、这一族零报。
  // 补丁把靶子弄崩（一条攻击都没发出）与补丁让静态层不再认它是候选，都会表现为零报——
  // 前者必须判不通过，后者只能在「别的族仍在打且业务没回退」时算过，并在 detail 里标明证据形态。
  const hardRuns = usable.get("hardened");
  let hardenedZero = null;
  if (!hardRuns.length) reasons.push(noRunReason("hardened"));
  else {
    const reported = [...new Set(hardRuns.flatMap((r) => [...vulnerableIds(r)].filter((id) => familyCaseIds.includes(id))))];
    const landed = hardRuns.map(lifeSigns);
    const regressed = [...new Set(landed.flatMap((l) => l.regressed))];
    const attackLanded = landed.reduce((n, l) => n + l.attackLanded, 0);
    const businessPassed = [...new Set(landed.flatMap((l) => l.businessPassed))];
    const directlyProbed = hardRuns.some((r) => expect.some((id) => String(r?.caseVerdicts?.[id] ?? "") !== ""));
    const detail = {
      attackLanded,
      businessPassed: businessPassed.length,
      evidence: reported.length ? "reported" : regressed.length ? "business_regressed" : !attackLanded ? "no_attack_traffic" : directlyProbed ? "probed_and_rejected" : "family_candidate_gone",
    };
    if (reported.length) {
      hardenedZero = gate(false, "failed", { ...detail, reported });
      reasons.push(`G2 加固版仍报：${reported.join(", ")}——补丁没修上，或这一族本来就不是那个补丁修的`);
    } else if (regressed.length) {
      hardenedZero = gate(false, "failed", { ...detail, regressed });
      reasons.push(`G2 加固版业务用例回退：${regressed.join(", ")}——补丁把功能改坏了，这一轮的「零报」不可信（崩掉的靶子当然不报漏洞）`);
    } else if (!attackLanded) {
      hardenedZero = gate(false, NOT_GRADED, detail);
      reasons.push("G2 加固版一条攻击请求都没发出去：零报不是证据，这一闸等于没考（要么靶子起不来，要么补丁把攻击面整个抹掉了）");
    } else {
      hardenedZero = gate(true, "passed", detail);
      if (!directlyProbed) {
        reasons.push(`G2 备注（不判失败）：加固版本族探针一条都没落地——静态层已不再把该路由当候选。这一闸靠的是「仍有 ${attackLanded} 条攻击请求落地 + ${businessPassed.length} 条业务用例通过 + 本族零报」，不是「同一发被运行期拒掉」。要运行期拒绝那种证据，得在第 8 项补一份「候选仍在、运行期拒」形状的考卷。`);
      }
    }
  }

  // —— G3 干净对照不许凭空造漏洞：这一份靶子里什么都没埋，报任何一条都是凭空造 ——
  const cleanRuns = usable.get("clean");
  let cleanControl = null;
  if (!cleanRuns.length) reasons.push(noRunReason("clean"));
  else {
    const fabricated = [];
    for (const r of cleanRuns) {
      for (const id of vulnerableIds(r)) if (!fabricated.includes(id)) fabricated.push(id);
      const outcome = String(r?.outcome ?? "");
      if (outcome.includes("vulnerable")) fabricated.push(`终态 ${outcome}`);
    }
    const landed = cleanRuns.map(lifeSigns);
    const attackLanded = landed.reduce((n, l) => n + l.attackLanded, 0);
    if (fabricated.length) {
      cleanControl = gate(false, "failed", { fabricated, attackLanded });
      reasons.push(`G3 干净对照凭空造出漏洞：${fabricated.join(", ")}`);
    } else if (!attackLanded) {
      cleanControl = gate(false, NOT_GRADED, { fabricated: [], attackLanded: 0 });
      reasons.push("G3 干净对照一条攻击请求都没落地：没有流量就没有「没造假」这回事，这一闸等于没考");
    } else {
      cleanControl = gate(true, "passed", { fabricated: [], attackLanded });
    }
  }

  // —— G4 连跑两次结论一致 ——
  const consistentPerVariant = {};
  const inconsistent = [];
  for (const v of VARIANTS) {
    const list = usable.get(v);
    if (list.length < 2) {
      consistentPerVariant[v] = null;
      continue;
    }
    const diffs = [];
    for (let i = 1; i < list.length; i++) diffs.push(...compareRuns(list[0], list[i]).map((d) => `${v} 第 ${i + 1} 次：${d}`));
    consistentPerVariant[v] = diffs.length === 0;
    if (diffs.length) inconsistent.push(...diffs);
  }
  const consistent = gate(
    VARIANTS.every((v) => consistentPerVariant[v] === true) && inconsistent.length === 0,
    inconsistent.length ? "failed" : NOT_GRADED,
    inconsistent.length ? { diffs: inconsistent } : undefined
  );
  if (!consistent.ok) reasons.push(`G4 两次跑结论不一致：${inconsistent.join("；") || "有变体跑不满两次，一致性无从验证"}`);

  const gates = {
    hit: hit ?? gate(false, NOT_GRADED),
    hardened_zero: hardenedZero ?? gate(false, NOT_GRADED),
    clean_control: cleanControl ?? gate(false, NOT_GRADED),
    consistent,
  };
  const graded = neverRan.length === 0 && missing.length === 0;
  const pass = graded && shortRuns.length === 0 && GATES.every((g) => gates[g].ok);
  if (neverRan.length) reasons.unshift(`这些变体一次都没跑：${neverRan.join(", ")}——没考不等于考过`);
  if (missing.length) reasons.unshift(`这些变体跑了但没有一次可用：${missing.join(", ")}`);
  if (shortRuns.length) reasons.unshift(`这些变体跑不满 repeat=${repeat}：${shortRuns.join(", ")}`);

  return {
    version: GRADE_VERSION,
    examId,
    recipe: exam?.recipe ?? null,
    family: exam?.family ?? null,
    repeat,
    graded,
    pass,
    gates,
    familyCaseIds,
    runs: runs.map((r) => ({
      variant: r?.variant,
      attempt: r?.attempt ?? null,
      exit: r?.exit ?? null,
      outcome: r?.outcome ?? null,
      usable: isUsable(r),
      vulnerable: [...(r?.vulnerableCaseIds ?? [])],
    })),
    reasons,
  };
}

/** 缺考卷的配方也要有一条明写的答案，不能让「没测」在汇总里消失 */
export function notGradedResult({ recipe, family, why }) {
  return {
    version: GRADE_VERSION,
    examId: null,
    recipe,
    family,
    graded: false,
    pass: false,
    gates: Object.fromEntries(GATES.map((g) => [g, gate(false, NOT_GRADED)])),
    reasons: [`没有考卷：${why}`],
  };
}

export function summarizeGrades(results) {
  const lines = [];
  for (const r of results ?? []) {
    const marks = GATES.map((g) => `${g}=${r?.gates?.[g]?.status ?? "?"}`).join(" ");
    lines.push(`- ${r.examId ?? r.recipe ?? "(未知)"}：${r.pass ? "通过" : r.graded ? "不通过" : "没考"} ${marks}`);
    for (const why of r.reasons ?? []) lines.push(`    ${why}`);
  }
  return lines.join("\n");
}
