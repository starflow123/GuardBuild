/**
 * Python 适配器单元测试：FastAPI / Flask / Django(DRF) 路由解析、Python 信号、
 * 候选判定与探测计划。运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  normalizePyPath,
  collectPythonSections,
  pySinkHints,
  pyOwnerGuard,
  pyOwnerFilter,
  pyRoleGuard,
  pyQueryParam,
} from "../lib/python.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { pythonHandlerParams, findSqlInjectionSignal, findTraversalSignal } from "../lib/signals.mjs";

const R = "\\\\?\\D:\\proj"; // Host 返回的 Windows 扩展路径前缀形态
const P = (...seg) => `${R}\\${seg.join("\\")}`;

test("normalizePyPath: FastAPI 花括号 / Flask & Django 转换器 → :param", () => {
  assert.equal(normalizePyPath("/orders/{order_id}", "fastapi"), "/orders/:order_id");
  assert.equal(normalizePyPath("/files/{file_path:path}", "fastapi"), "/files/:file_path");
  assert.equal(normalizePyPath("/orders/<int:order_id>/", "flask"), "/orders/:order_id");
  assert.equal(normalizePyPath("/orders/<int:pk>/cancel/", "django"), "/orders/:pk/cancel");
  assert.equal(normalizePyPath("v1/orders", "fastapi"), "/v1/orders");
  assert.equal(normalizePyPath("/", "fastapi"), "/");
  assert.equal(normalizePyPath("", "fastapi"), null);
});

test("collectPythonSections: FastAPI APIRouter 前缀 + 跨文件 include_router 折叠", () => {
  const files = [
    {
      path: P("app", "main.py"),
      content: [
        "from fastapi import FastAPI",
        "from .routers import orders",
        "",
        "app = FastAPI()",
        'app.include_router(orders.router, prefix="/v1")',
      ].join("\n"),
    },
    {
      path: P("app", "routers", "orders.py"),
      content: [
        "from fastapi import APIRouter, Depends, Query",
        "",
        'router = APIRouter(prefix="/orders", tags=["orders"])',
        "",
        '@router.get("/{order_id}")',
        "def detail(order_id: int, user: dict = Depends(get_current_user), db=Depends(get_db)):",
        "    order = db.query(Order).filter(Order.id == order_id).first()",
        '    return {"order": order}',
        "",
        '@router.get("/search")',
        "def search(q: str = Query(None), user: dict = Depends(get_current_user)):",
        "    return []",
        "",
        '@router.api_route("/multi", methods=["GET", "DELETE"])',
        "def multi():",
        "    return {}",
      ].join("\n"),
    },
  ];
  const { sections, diag } = collectPythonSections(files);
  assert.equal(diag.fastapiFiles, 1);
  assert.equal(diag.fastapiRoutes, 4, "GET detail + GET search + api_route 的 GET/DELETE");

  const detail = sections.find((s) => s.method === "GET" && s.declaredPath === "/v1/orders/:order_id");
  assert.ok(detail, "APIRouter prefix 与 include_router prefix 应折叠为完整路径");
  assert.equal(detail.forcedAuth, true, "Depends(get_current_user) 应识别为鉴权");
  assert.ok(detail.sinkHints.some((h) => h.call === "query.filter"), "SQLAlchemy 取数应进入 sinkHints");
  assert.ok(detail.sinkHints.some((h) => h.call === "first"));
  assert.equal(detail.queryParamHint, null, "路径参数不应误判为查询参数");
  assert.equal(detail.ownerGuard, false);

  const search = sections.find((s) => s.declaredPath === "/v1/orders/search");
  assert.deepEqual(search.queryParamHint, { param: "q", form: "signature" });

  const methods = sections.filter((s) => s.declaredPath === "/v1/orders/multi").map((s) => s.method).sort();
  assert.deepEqual(methods, ["DELETE", "GET"], "api_route 的 methods 列表应逐个展开，且不把路径字面量当方法");
});

test("collectPythonSections: Flask Blueprint url_prefix + register_blueprint 前缀", () => {
  const files = [
    {
      path: P("shop", "app.py"),
      content: [
        "from flask import Flask",
        "from .orders import bp",
        "",
        "app = Flask(__name__)",
        'app.register_blueprint(bp, url_prefix="/api")',
      ].join("\n"),
    },
    {
      path: P("shop", "orders.py"),
      content: [
        "from flask import Blueprint, request",
        "",
        'bp = Blueprint("orders", __name__, url_prefix="/orders")',
        "",
        '@bp.route("/<int:order_id>", methods=["GET", "DELETE"])',
        "def detail(order_id):",
        "    order = Order.query.filter_by(id=order_id).first()",
        '    return {"order": order}',
        "",
        '@bp.get("/search")',
        "def search():",
        '    target = request.args.get("file")',
        "    return open(target).read()",
      ].join("\n"),
    },
  ];
  const { sections, diag } = collectPythonSections(files);
  assert.equal(diag.flaskFiles, 1);
  assert.equal(diag.flaskRoutes, 3);

  const detail = sections.find((s) => s.method === "GET" && s.declaredPath === "/api/orders/:order_id");
  assert.ok(detail, "Blueprint url_prefix 与 register_blueprint url_prefix 应折叠");
  assert.equal(detail.forcedAuth, false, "无鉴权信号的 Flask 视图应保持公开");
  assert.ok(detail.sinkHints.some((h) => h.call === "filter_by"));
  assert.ok(sections.some((s) => s.method === "DELETE" && s.declaredPath === "/api/orders/:order_id"));

  const search = sections.find((s) => s.declaredPath === "/api/orders/search");
  assert.deepEqual(search.queryParamHint, { param: "file", form: "request" }, "request.args.get 应识别为查询参数");
});

test("collectPythonSections: Django include 前缀 + 函数/类视图 + DRF ViewSet", () => {
  const files = [
    {
      path: P("shop", "urls.py"),
      content: [
        "from django.urls import path, include",
        "from . import views",
        "",
        "urlpatterns = [",
        '    path("api/", include("shop.api_urls")),',
        '    path("v1/orders/<int:pk>/", views.order_detail, name="order-detail"),',
        '    path("v1/orders/<int:pk>/cancel/", views.OrderCancelView.as_view(), name="order-cancel"),',
        "]",
      ].join("\n"),
    },
    {
      path: P("shop", "api_urls.py"),
      content: [
        "from django.urls import path, include",
        "from rest_framework import routers",
        "from .views import OrderViewSet",
        "",
        "router = routers.DefaultRouter()",
        'router.register(r"orders", OrderViewSet)',
        "",
        'urlpatterns = [path("drf/", include(router.urls))]',
      ].join("\n"),
    },
    {
      path: P("shop", "views.py"),
      content: [
        "from django.contrib.auth.decorators import login_required",
        "from django.http import JsonResponse",
        "from django.shortcuts import get_object_or_404",
        "from django.views import View",
        "from rest_framework.permissions import IsAuthenticated",
        "from rest_framework.viewsets import ModelViewSet",
        "",
        "@login_required",
        "def order_detail(request, pk):",
        "    order = get_object_or_404(Order, pk=pk)",
        '    return JsonResponse({"order": order.id})',
        "",
        "class OrderCancelView(View):",
        "    def post(self, request, pk):",
        "        order = Order.objects.get(pk=pk)",
        '        order.status = "cancelled"',
        '        return JsonResponse({"ok": True})',
        "",
        "class OrderViewSet(ModelViewSet):",
        "    permission_classes = [IsAuthenticated]",
        "    queryset = Order.objects.all()",
        "",
        "    def get_queryset(self):",
        "        return Order.objects.filter(user=self.request.user)",
      ].join("\n"),
    },
  ];
  const { sections, diag } = collectPythonSections(files);
  assert.equal(diag.drfViewSets, 1);
  assert.equal(diag.djangoUrls, 6, "函数视图 1 + 类视图 1 + ViewSet 4 个动作");

  const fn = sections.find((s) => s.method === "GET" && s.declaredPath === "/v1/orders/:pk");
  assert.ok(fn, "path() + 函数视图应生成区块");
  assert.equal(fn.forcedAuth, true, "@login_required 应识别为鉴权");
  assert.ok(fn.sinkHints.some((h) => h.call === "get_object_or_404"));

  const cls = sections.find((s) => s.method === "POST" && s.declaredPath === "/v1/orders/:pk/cancel");
  assert.ok(cls, "class View.as_view() 应按类内 def post 生成 POST 区块");
  assert.equal(cls.forcedAuth, false);
  assert.ok(cls.sinkHints.some((h) => h.call === "objects.get"));

  const drf = sections.filter((s) => s.declaredPath === "/api/drf/orders/:pk");
  assert.deepEqual(
    drf.map((s) => s.method).sort(),
    ["DELETE", "GET", "PATCH", "PUT"],
    "ModelViewSet 应展开详情动作"
  );
  assert.ok(drf.every((s) => s.forcedAuth === true), "permission_classes = [IsAuthenticated] 应识别为鉴权");
  assert.ok(drf.every((s) => s.ownerFilter === true), "get_queryset 按 request.user 过滤应抑制误报");
});

test("Python 信号：sink 惯用法 / 归属校验与过滤 / 角色守卫 / 查询参数", () => {
  const sinks = pySinkHints(
    [
      "Order.objects.get(pk=pk)",
      "get_object_or_404(Receipt, pk=pk)",
      "session.query(Order).filter(Order.id == pk).first()",
      "Order.query.filter_by(id=pk).first()",
      "select(Order.id).where(Order.id == pk)",
    ].join("\n")
  );
  const calls = sinks.map((h) => h.call);
  for (const call of ["objects.get", "get_object_or_404", "query.filter", "filter_by", "select.where", "first"]) {
    assert.ok(calls.includes(call), `应识别 ${call}`);
  }

  assert.equal(pyOwnerGuard("    if order.user_id != current_user.id:\n        raise Forbidden"), true);
  assert.equal(pyOwnerGuard('    if order["userId"] != user["id"]:\n        raise Forbidden'), true);
  assert.equal(pyOwnerGuard('    if order.status != "paid":\n        raise Conflict'), false, "业务状态判断不应视为归属校验");

  assert.equal(pyOwnerFilter("Order.query.filter(Order.user_id == current_user.id)"), true);
  assert.equal(pyOwnerFilter("Order.objects.filter(user=self.request.user)"), true);
  assert.equal(pyOwnerFilter("Order.query.filter(Order.id == order_id)"), false);

  assert.equal(pyRoleGuard("@require_admin"), true);
  assert.equal(pyRoleGuard('if current_user.role != "admin":'), true);
  assert.equal(pyRoleGuard("permission_classes = [IsAdminUser]"), true);
  assert.equal(pyRoleGuard('if order.status != "paid":'), false);

  assert.deepEqual(pyQueryParam('request.args.get("file")'), { param: "file", form: "request" });
  assert.deepEqual(pyQueryParam('request.GET["path"]'), { param: "path", form: "request" });
  assert.equal(pyQueryParam("request.json['id']"), null);
});

test("analyzeProject: FastAPI 靶场生成 3 个候选并规划探测计划", async () => {
  const fixturePath = fileURLToPath(new URL("../../fixtures/python-shop/main.py", import.meta.url));
  const content = readFileSync(fixturePath, "utf8");
  const contents = new Map([[P("main.py"), content]]);
  const listing = { entries: [...contents.keys()].map((p) => ({ path: p, kind: "file", size: content.length })) };
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") {
          return { content: contents.get(params.path), size: content.length, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  });

  assert.equal(a.diagnostics.pythonFastapiRoutes, 7, "均应解析 FastAPI 装饰器路由");
  const pairs = a.candidates.map((c) => `${c.method} ${c.path}`).sort();
  assert.deepEqual(pairs, [
    "GET /api/orders/:order_id",
    "GET /api/receipts/:receipt_id",
    "POST /api/orders/:order_id/cancel",
  ]);

  const readCand = a.candidates.find((c) => c.path === "/api/orders/:order_id");
  assert.equal(readCand.kind, "idor-suspect");
  assert.equal(readCand.style, "python");
  assert.equal(readCand.hasAuth, true);
  assert.equal(readCand.hasOwnerGuard, false);
  assert.equal(readCand.resource, "order", "db.query(Order) 应归约为资源名 order");

  const anonCand = a.candidates.find((c) => c.path === "/api/receipts/:receipt_id");
  assert.equal(anonCand.kind, "no-auth-suspect");
  assert.equal(anonCand.hasAuth, false);

  assert.ok(!a.candidates.some((c) => c.path === "/api/orders"), "归属过滤的列表接口不应成为候选");
  assert.ok(!a.candidates.some((c) => c.path.startsWith("/api/admin")), "require_admin 守卫的角色接口不应成为候选");

  const plan = buildProbePlan(a);
  assert.equal(plan.readCandidate?.path, "/api/orders/:order_id");
  assert.equal(plan.cancelCandidate?.path, "/api/orders/:order_id/cancel");
  assert.equal(plan.unauthReadCandidate?.path, "/api/receipts/:receipt_id");
  assert.equal(plan.listEndpoint?.path, "/api/orders");
  assert.equal(plan.adminListEndpoint?.path, "/api/admin/orders");
  assert.equal(plan.adminCancelEndpoint?.path, "/api/admin/orders/:order_id/cancel");
  assert.equal(plan.resource, "order");
});

/** 复刻开源靶场 vulnapi 的形态：FastAPI 查询参数是函数形参（不写 request.args），
 *  值经 f-string / 拼接进入 SQL 与文件读取。修复前这两条链路都是漏报。 */
const RANGE_MAIN = [
  'from fastapi import FastAPI, Request',
  "import sqlite3, os, time",
  "",
  "app = FastAPI()",
  'sqldb = sqlite3.connect("data.sqlite")',
  "",
  '@app.get("/bank_codes/")',
  'async def read_some_bank_codes(request: Request, code="1"):',
  "    query = sqldb.cursor()",
  '    parameter = f"select * from bank_codes where code=\'{code}\';"',
  '    results = query.execute(parameter).fetchone()',
  "    return {\"code\": results[1]}",
  "",
  '@app.get("/exchangerate/")',
  'async def get_exchange_rates(request: Request, datestamp=time.strftime("%Y-%m-%d")):',
  '    if os.path.exists("./data/" + datestamp):',
  '        return open("./data/" + datestamp).read()',
  '    return {"error": "missing"}',
].join("\n");

test("pythonHandlerParams: FastAPI 形参（字面量默认值/无注解）即查询参数", () => {
  const sqliText = RANGE_MAIN.slice(RANGE_MAIN.indexOf('@app.get("/bank_codes/")'));
  assert.deepEqual(pythonHandlerParams(sqliText.slice(0, 320)), [{ name: "code", channel: "query" }]);
  const travText = RANGE_MAIN.slice(RANGE_MAIN.indexOf('@app.get("/exchangerate/")'));
  assert.deepEqual(pythonHandlerParams(travText), [{ name: "datestamp", channel: "query" }]);
});

test("Python 信号：形参污点进入 query.execute 与 open 拼接", () => {
  const sqliText = RANGE_MAIN.slice(RANGE_MAIN.indexOf('@app.get("/bank_codes/")'), RANGE_MAIN.indexOf('@app.get("/exchangerate/")'));
  assert.deepEqual(findSqlInjectionSignal(sqliText), {
    source: "query",
    param: "code",
    sink: "execute",
    form: "variable",
  });

  const travText = RANGE_MAIN.slice(RANGE_MAIN.indexOf('@app.get("/exchangerate/")'));
  const trav = findTraversalSignal(travText);
  assert.equal(trav.param, "datestamp");
  assert.equal(trav.sink, "open");
  assert.equal(trav.source, "query");
});

test("analyzeProject: FastAPI 形参链路产出 sqli/traversal 候选", async () => {
  const path = P("main.py");
  const listing = { entries: [{ path, kind: "file", size: RANGE_MAIN.length }] };
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") return { content: RANGE_MAIN, size: RANGE_MAIN.length, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const byKind = Object.fromEntries(a.candidates.map((c) => [c.kind, c]));
  assert.equal(byKind["sqli-suspect"]?.path, "/bank_codes");
  assert.equal(byKind["sqli-suspect"]?.sqli.param, "code");
  assert.equal(byKind["traversal-suspect"]?.path, "/exchangerate");
  assert.equal(byKind["traversal-suspect"]?.traversal.param, "datestamp");

  const plan = buildProbePlan(a);
  assert.ok(plan.sqliCandidate || plan.traversalCandidate, "注入类候选要进入探测计划");
});
