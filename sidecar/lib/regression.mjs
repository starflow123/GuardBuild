/**
 * 不许回退：把「本轮哪些键是绿的」快照存进仓库，复跑时逐键比对，红一条即整轮否决。
 *
 * 为什么单独有这一层：基准脚本本身已经要求「全部靶场通过」，但那是完整跑的口径。
 * 一旦按套件分批跑（--only）、或者以后由调优环只跑受影响的一族，
 * 「平均分上涨」就会掩盖「另一族从绿变红」。这里不看平均，只看有没有绿→红。
 *
 * 一条关键约束：**失败的键不许被自动从绿名单里删掉**。
 * 否则一次改坏会顺手把自己的必过项删除，回退网就成了会自动缩小的门。
 * 想让绿名单变小只能显式 --rebaseline，且那一轮必须本身全绿，否则拒绝。
 */
import fs from "node:fs";

export const BASELINE_VERSION = "gb-green-baseline-1";

export function emptyBaseline() {
  return { version: BASELINE_VERSION, updatedAt: null, suites: {} };
}

export function readBaseline(filePath) {
  if (!fs.existsSync(filePath)) return emptyBaseline();
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (parsed?.version !== BASELINE_VERSION || !parsed.suites) return emptyBaseline();
    return parsed;
  } catch {
    return emptyBaseline();
  }
}

/** 键形状：`suite/target` 或 `suite/target#caseKey` */
export function targetOfKey(suite, key) {
  const rest = key.startsWith(`${suite}/`) ? key.slice(suite.length + 1) : key;
  return rest.split("#")[0];
}

export function compare({ baseline, suite, currentKeys, coveredTargets, corpusVersion = null, gitHead = null, now = new Date().toISOString() }) {
  const prev = baseline.suites?.[suite]?.keys ?? [];
  const current = new Set(currentKeys);
  const covered = coveredTargets ?? new Set(currentKeys.map((k) => targetOfKey(suite, k)));
  const coveredSet = covered instanceof Set ? covered : new Set(covered);

  const regressions = prev.filter((k) => coveredSet.has(targetOfKey(suite, k)) && !current.has(k));
  const improvements = [...current].filter((k) => !prev.includes(k));
  const checked = prev.filter((k) => coveredSet.has(targetOfKey(suite, k))).length;

  // 并集而不是替换：绿→红的键必须留在名单里继续追，只有 --rebaseline 能缩小名单
  const mergedKeys = [...new Set([...prev, ...current])].sort();
  const next = {
    ...baseline,
    updatedAt: now,
    suites: {
      ...baseline.suites,
      [suite]: {
        keys: mergedKeys.sort(),
        lastRunAt: now,
        lastRunHead: gitHead,
        corpusVersion: corpusVersion ?? baseline.suites?.[suite]?.corpusVersion ?? null,
        regressions: regressions.length,
      },
    },
  };

  return { ok: regressions.length === 0, regressions, improvements, checked, baseline: next };
}

/**
 * @param {boolean} rebaseline 显式重建绿名单（只允许在全绿轮次使用）
 * @param {boolean} partial --only 这类局部跑：只比对被覆盖的靶场，不缩名单
 */
export function gateAgainstBaseline({ filePath, suite, currentKeys, coveredTargets, corpusVersion = null, gitHead = null, allPass = true, partial = false, rebaseline = false }) {
  const baseline = readBaseline(filePath);
  const before = baseline.suites?.[suite]?.keys?.length ?? 0;

  if (rebaseline && !allPass) {
    return { ok: false, reason: "refuse_rebaseline", regressions: [], improvements: [], baselineKeys: before, baselineUpdated: false };
  }

  const result = compare({ baseline, suite, currentKeys, coveredTargets, corpusVersion, gitHead });
  let next = result.baseline;
  let baselineUpdated = true;

  if (rebaseline) {
    next = {
      ...next,
      suites: { ...next.suites, [suite]: { ...next.suites[suite], keys: [...new Set(currentKeys)].sort() } },
    };
  } else if (partial) {
    // 局部跑不写盘：一次 --only 的样本不该更新整份名单的时间戳与统计
    baselineUpdated = false;
  }

  if (baselineUpdated) {
    fs.writeFileSync(filePath, `${JSON.stringify(next, null, 2)}\n`);
  }

  return {
    ok: rebaseline ? true : result.ok,
    reason: rebaseline ? "rebaselined" : result.ok ? "clean" : "regression",
    regressions: result.regressions,
    improvements: rebaseline ? [] : result.improvements,
    baselineKeys: rebaseline ? currentKeys.length : next.suites[suite].keys.length,
    previousKeys: before,
    baselineUpdated,
  };
}
