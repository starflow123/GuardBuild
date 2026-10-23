import test from "node:test";
import assert from "node:assert/strict";
import {
  buildImportGraph,
  createDirAllowed,
  CLOSURE_CAPS,
  expandWriteSet,
  extractRelativeImports,
  graphToJSON,
  inDegree,
  resolveSpec,
  reviveGraph,
  toRel,
} from "../lib/depgraph.mjs";

const graphOf = (files) => buildImportGraph(files);

test("toRel: 兼容 Host 的 \\\\?\\ 扩展前缀与两种路径形态", () => {
  assert.equal(toRel("\\\\?\\D:\\p\\demo", "\\\\?\\D:\\p\\demo\\src\\app.js"), "src/app.js");
  // 根与文件形态不一致时按字面前缀剥离（大小写不敏感）
  assert.equal(toRel("D:\\p\\demo", "\\\\?\\D:\\p\\demo\\src\\a\\b.py"), "src/a/b.py");
  assert.equal(toRel("d:/p/demo", "D:/P/demo/src/app.js"), "src/app.js");
  // 越出根目录不成相对路径
  assert.equal(toRel("D:/p/demo", "D:/other/src/app.js"), null);
  assert.equal(toRel("D:/p/demo", "D:/p/demo"), "");
  assert.equal(toRel("", "D:/p/a.js"), null);
});

test("extractRelativeImports: 抓 require/import/动态 import 与 Python 相对导入，忽略裸包名", () => {
  const js = extractRelativeImports(
    `const db = require('./db');\nimport guard from "../middleware/auth";\nexport { x } from "./lib/extra";\nconst lazy = await import("./late");\nimport express from "express";`
  );
  assert.deepEqual(new Set(js), new Set(["./db", "../middleware/auth", "./lib/extra", "./late"]));
  const py = extractRelativeImports("from ..db import get_conn\nfrom .services.auth import guard\nfrom flask import Flask");
  assert.deepEqual(new Set(py), new Set(["../db", "./services/auth"]));
});

test("resolveSpec: 补扩展名与 index 形态，bare 说明符不入图", () => {
  const known = new Set(["src/db.js", "src/lib/index.ts", "src/nested/deep.py"]);
  assert.equal(resolveSpec("src/app.js", "./db", known), "src/db.js");
  assert.equal(resolveSpec("src/app.js", "./lib", known), "src/lib/index.ts");
  assert.equal(resolveSpec("src/a/b.py", "../nested/deep", known), "src/nested/deep.py");
  assert.equal(resolveSpec("src/app.js", "express", known), null);
  assert.equal(resolveSpec("src/app.js", "./missing", known), null);
});

test("buildImportGraph: 双向边成对登记，自引用与未知目标不污染图", () => {
  const { nodes, unresolved } = graphOf([
    { rel: "src/app.js", content: `import db from "./db"; import self from "./app";` },
    { rel: "src/db.js", content: `module.exports = {}` },
    { rel: "src/orphan.js", content: "" },
  ]);
  assert.deepEqual([...nodes.get("src/app.js").out], ["src/db.js"]);
  assert.deepEqual([...nodes.get("src/db.js").in], ["src/app.js"]);
  assert.equal(nodes.get("src/app.js").in.size, 0, "自引用不应写进 in");
  assert.equal(unresolved, 0, "自引用能被解析（不算未决），只是不参与闭包");
});

test("expandWriteSet: 正向 2 层 6 文件、反向 1 层 4 文件封顶，越界按广度截断", () => {
  // 正向链：seed → f1 → f2 → f3（f3 超过深度 2）
  const chain = [
    { rel: "seed.js", content: `import "./f1";` },
    { rel: "f1.js", content: `import "./f2";` },
    { rel: "f2.js", content: `import "./f3";` },
    { rel: "f3.js", content: `` },
  ];
  const chainNodes = graphOf(chain).nodes;
  const w1 = expandWriteSet({ nodes: chainNodes, seeds: ["seed.js"] });
  assert.equal(w1.roles.get("seed.js"), "candidate");
  assert.equal(w1.roles.get("f1.js"), "forward");
  assert.equal(w1.roles.get("f2.js"), "forward");
  assert.ok(!w1.roles.has("f3.js"), "深度 2 之外的文件不入写集");

  // 反向：10 个 importer 只有前 4 个进写集（reverseFiles 上限）
  const many = [{ rel: "hub.js", content: "" }];
  for (let i = 0; i < 10; i++) many.push({ rel: `use${i}.js`, content: `import "./hub";` });
  const hubNodes = graphOf(many).nodes;
  const w2 = expandWriteSet({ nodes: hubNodes, seeds: ["hub.js"] });
  const reverse = [...w2.roles.entries()].filter(([, r]) => r === "reverse");
  assert.equal(reverse.length, CLOSURE_CAPS.reverseFiles);
  assert.equal(w2.roles.get("use0.js"), "reverse");

  // 关闭开关时只给候选文件本身
  const off = expandWriteSet({ nodes: hubNodes, seeds: ["hub.js"], enabled: false });
  assert.deepEqual([...off.roles.entries()], [["hub.js", "candidate"]]);
});

test("expandWriteSet: newFileDirs 只含已有源码目录，rolesLower 按小写键匹配模型给出的路径", () => {
  const nodes = graphOf([
    { rel: "src/routes/a.js", content: `import db from "../db";` },
    { rel: "src/db.js", content: "" },
  ]).nodes;
  const w = expandWriteSet({ nodes, seeds: ["src/routes/a.js"] });
  assert.deepEqual(w.newFileDirs, ["src", "src/routes"]);
  assert.equal(w.rolesLower.get("SRC/DB.JS".toLowerCase()), "forward", "大小写差异不影响写集匹配（调用方按小写键查）");
  assert.equal(inDegree(nodes, "src/db.js"), 1);
});

test("createDirAllowed: 只允许在已扫描到源码的目录里新建文件", () => {
  const dirs = ["src", "src/routes"];
  assert.equal(createDirAllowed("src/guards/x.js", dirs).ok, false, "guards/ 不存在于源码目录清单");
  assert.equal(createDirAllowed("src/routes/guard.js", dirs).ok, true);
  assert.equal(createDirAllowed("guard.js", dirs).ok, false, "无父目录");
  assert.equal(createDirAllowed("../evil.js", dirs).ok, false);
});

test("graphToJSON / reviveGraph: 序列化往返保持边与规模", () => {
  const g = graphOf([
    { rel: "a.js", content: `import "./b";` },
    { rel: "b.js", content: `import "./c";` },
    { rel: "c.js", content: "" },
  ]);
  const json = graphToJSON(g);
  assert.equal(json.nodes.length, 3);
  const revived = reviveGraph(json);
  assert.deepEqual([...revived.get("a.js").out], ["b.js"]);
  assert.deepEqual([...revived.get("c.js").in], ["b.js"]);
  assert.deepEqual(reviveGraph(null), new Map());
});
