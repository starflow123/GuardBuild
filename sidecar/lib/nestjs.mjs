/**
 * NestJS 适配器：控制器装饰器路由（@Controller/@Get/@Post…）静态解析。
 *
 * 产出统一形态的「伪区块」（style: "nest"）：真实 URL 路径（全局前缀 setGlobalPrefix
 * + 控制器前缀 + 方法子路径）+ HTTP 方法 + 处理器正文（拼接类级装饰器块，
 * 使 @UseGuards 等类级守卫对全部方法可见）。动态复现复用 HTTP 泛化探测引擎——
 * 探测层只认「路径 + 方法 + 身份」，不关心服务端框架。
 *
 * 说明：NestJS 的修复涉及守卫/管道依赖注入形态多元，v1 不提供自动修复策略；
 * 探测到漏洞证据时按 vulnerable_unfixed 阻断并给出人工修复指引。
 */
import { braceSpan, callArgsSpan, findBodyOpen } from "./signals.mjs";

const METHOD_OF = {
  Get: "GET",
  Post: "POST",
  Put: "PUT",
  Patch: "PATCH",
  Delete: "DELETE",
  Head: "HEAD",
  Options: "OPTIONS",
  All: "GET", // @All 覆盖全部方法，按 GET 参与「单体资源读」形态判定
};

const lineOf = (content, index) => content.slice(0, index).split("\n").length;

/** 从装饰器行起向上纳入连续的装饰器/注释行（类级守卫常写在 @Controller 上方） */
function decoratorBlockStart(content, idx) {
  let start = idx;
  while (start > 0) {
    const lineStart = content.lastIndexOf("\n", start - 2) + 1;
    const line = content.slice(lineStart, start - 1).trim();
    if (/^@[A-Za-z_$]/.test(line) || line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) {
      start = lineStart;
      continue;
    }
    break;
  }
  return start;
}

/** @Controller 实参 → 路由前缀：优先 path 属性（对象实参），否则首个字符串字面量 */
function controllerPrefix(argsText) {
  const p = /path\s*:\s*["'`]([^"'`]*)["'`]/.exec(argsText);
  if (p) return p[1];
  const s = /["'`]([^"'`]*)["'`]/.exec(argsText);
  return s ? s[1] : "";
}

/** 跳过方法签名前的剩余装饰器（@UseGuards/@Roles/@HttpCode 等，可带实参或裸名） */
function skipDecorators(content, p) {
  for (;;) {
    const ws = /^[ \t\r\n]*/.exec(content.slice(p))[0];
    p += ws.length;
    if (content[p] !== "@") return p;
    const name = /^@[A-Za-z_$][\w$]*/.exec(content.slice(p));
    if (!name) return p;
    p += name[0].length;
    const gap = /^[ \t\r\n]*/.exec(content.slice(p))[0];
    const q = p + gap.length;
    if (content[q] === "(") {
      const args = callArgsSpan(content, q);
      if (args === null) return p;
      p = q + args.length + 2;
    }
  }
}

/**
 * 提取文件中的控制器（含类级装饰器块与类体范围）。
 * 返回 [{ prefix, headerText, bodyStart, classEnd }]
 */
export function extractControllers(content) {
  const out = [];
  const ctrlRe = /^[ \t]*@Controller\s*\(/gm;
  let m;
  while ((m = ctrlRe.exec(content))) {
    const openIdx = m.index + m[0].length - 1;
    const args = callArgsSpan(content, openIdx);
    if (args === null) continue;
    const after = openIdx + args.length + 2;
    const classM = /class\s+[A-Za-z_$][\w$]*\b[^{;]*\{/.exec(content.slice(after));
    if (!classM) continue;
    const classOpen = after + classM.index + classM[0].length - 1;
    const classEnd = braceSpan(content, classOpen);
    if (classEnd < 0) continue;
    out.push({
      prefix: controllerPrefix(args),
      headerText: content.slice(decoratorBlockStart(content, m.index), classOpen + 1),
      bodyStart: classOpen + 1,
      classEnd,
    });
  }
  return out;
}

/**
 * 提取控制器内的装饰器方法处理器。
 * 返回 [{ method, subPath, startLine, text }]（text 自方法装饰器块起至方法体闭合）
 */
export function extractControllerMethods(content, ctrl) {
  const out = [];
  const re = /^[ \t]*@(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(/gm;
  re.lastIndex = ctrl.bodyStart;
  let m;
  while ((m = re.exec(content))) {
    if (m.index >= ctrl.classEnd) break;
    const openIdx = m.index + m[0].length - 1;
    const args = callArgsSpan(content, openIdx);
    if (args === null) continue;
    const lit = /["'`]([^"'`]*)["'`]/.exec(args);
    const subPath = lit ? lit[1] : "";
    let p = skipDecorators(content, openIdx + args.length + 2);
    const sigRe = /(?:(?:public|private|protected|static|async)\s+)*[A-Za-z_$][\w$]*\s*\(/y;
    sigRe.lastIndex = p;
    const sigM = sigRe.exec(content);
    if (!sigM) continue;
    const bodyOpen = findBodyOpen(content, p + sigM[0].length - 1);
    if (bodyOpen < 0) continue;
    const bodyEnd = braceSpan(content, bodyOpen);
    if (bodyEnd < 0) continue;
    const textStart = Math.max(decoratorBlockStart(content, m.index), ctrl.bodyStart);
    out.push({
      method: METHOD_OF[m[1]],
      subPath,
      startLine: lineOf(content, textStart),
      text: content.slice(textStart, bodyEnd + 1),
    });
  }
  return out;
}

function joinUrl(...parts) {
  const segs = parts
    .filter((p) => p && String(p).trim())
    .map((p) => String(p).replace(/^\/+|\/+$/g, ""))
    .filter(Boolean);
  return "/" + segs.join("/");
}

/**
 * 汇总 NestJS 控制器路由区块。files 为 [{ path, content }]。
 * 返回 { sections, diag }——sections 与 express 区块同构，style 固定 "nest"。
 */
export function collectNestSections(files) {
  const sections = [];
  const diag = { nestFiles: 0, nestControllers: 0, nestHandlers: 0, nestGlobalPrefix: null };
  let globalPrefix = "";
  for (const f of files) {
    const gp = /setGlobalPrefix\s*\(\s*["'`]([^"'`]+)["'`]/.exec(f.content ?? "");
    if (gp && !globalPrefix) {
      globalPrefix = gp[1];
      diag.nestGlobalPrefix = gp[1];
    }
  }
  for (const f of files) {
    const content = f.content ?? "";
    const ctrls = extractControllers(content);
    if (ctrls.length === 0) continue;
    diag.nestFiles += 1;
    for (const ctrl of ctrls) {
      diag.nestControllers += 1;
      for (const h of extractControllerMethods(content, ctrl)) {
        diag.nestHandlers += 1;
        sections.push({
          file: f.path,
          startLine: h.startLine,
          method: h.method,
          style: "nest",
          declaredPath: joinUrl(globalPrefix, ctrl.prefix, h.subPath),
          text: ctrl.headerText + "\n" + h.text,
        });
      }
    }
  }
  return { sections, diag };
}
