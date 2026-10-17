"""PythonShop：FastAPI 复刻靶场（GuardBuild Python 适配器的被测对象）。

复刻三类漏洞：
  1. GET  /api/orders/{order_id}          登录后按 id 取单，未校验归属（IDOR）
  2. POST /api/orders/{order_id}/cancel   登录后按 id 取消，未校验归属（越权写）
  3. GET  /api/receipts/{receipt_id}      无鉴权即可读小票（匿名越权）

基线接口 /api/admin/orders 有管理员依赖，/api/orders 列表按归属过滤——
用于回归防线：合法的业务能力必须在修复后继续可用。

取数使用与 SQLAlchemy 同形的 FakeDB.query(Model).filter(...).first()，
使静态适配器能识别 Python ORM 惯用法；运行时由本文件内的内存表承载。
"""
import os
import uuid

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException

app = FastAPI(title="PythonShop")
router = APIRouter(prefix="/api")


class Column:
    """列描述符：Order.id == 1 → 行谓词（对齐 SQLAlchemy 的表达式形态）"""

    def __init__(self, name: str):
        self.name = name

    def __eq__(self, other):
        return lambda row: row.get(self.name) == other


class Order:
    id = Column("id")
    user_id = Column("userId")
    status = Column("status")


class Receipt:
    id = Column("id")
    user_id = Column("userId")


class Query:
    def __init__(self, db, model):
        self.db = db
        self.model = model
        self.pred = None

    def filter(self, pred):
        self.pred = pred
        return self

    def first(self):
        for row in self.db.tables[self.model.__name__]:
            if self.pred is None or self.pred(row):
                return row
        return None

    def all(self):
        return [row for row in self.db.tables[self.model.__name__] if self.pred is None or self.pred(row)]


class FakeDB:
    def __init__(self):
        self.tables = {"Order": [], "Receipt": []}

    def query(self, model):
        return Query(self, model)


DB = FakeDB()
DB.tables["Order"] = [
    {
        "id": 1,
        "userId": "u-alice",
        "title": "Alice 的机械键盘",
        "amount": 399,
        "status": "paid",
        "address": "北京市海淀区中关村大街 1 号",
    },
    {
        "id": 2,
        "userId": "u-bob",
        "title": "Bob 的 4K 显示器",
        "amount": 1299,
        "status": "paid",
        "address": "上海市浦东新区世纪大道 2 号",
    },
]
DB.tables["Receipt"] = [
    {
        "id": 2,
        "userId": "u-bob",
        "title": "Bob 的 4K 显示器",
        "amount": 1299,
        "status": "paid",
        "address": "上海市浦东新区世纪大道 2 号",
    },
]

USERS = {
    "alice@py.shop": {"id": "u-alice", "email": "alice@py.shop", "password": "alice123", "role": "user"},
    "bob@py.shop": {"id": "u-bob", "email": "bob@py.shop", "password": "bob123", "role": "user"},
    "admin@py.shop": {"id": "u-admin", "email": "admin@py.shop", "password": "admin123", "role": "admin"},
}
TOKENS = {}


def get_db() -> FakeDB:
    return DB


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未认证")
    user = TOKENS.get(authorization.removeprefix("Bearer "))
    if not user:
        raise HTTPException(status_code=401, detail="无效凭证")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


@app.post("/api/login")
def login(payload: dict):
    user = next(
        (
            u
            for u in USERS.values()
            if u["email"] == payload.get("email") and u["password"] == payload.get("password")
        ),
        None,
    )
    if not user:
        raise HTTPException(status_code=401, detail="邮箱或密码错误")
    token = uuid.uuid4().hex
    TOKENS[token] = user
    return {"token": token, "user": user}


@app.get("/api/orders")
def list_orders(user: dict = Depends(get_current_user), db: FakeDB = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == user["id"]).all()
    return {"orders": orders}


@router.get("/orders/{order_id}")
def get_order(order_id: int, user: dict = Depends(get_current_user), db: FakeDB = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="订单不存在")
    # 复刻漏洞：仅按 id 取单，未校验 order.userId 是否属于当前用户
    return {"order": order}


@router.post("/orders/{order_id}/cancel")
def cancel_order(order_id: int, user: dict = Depends(get_current_user), db: FakeDB = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="订单不存在")
    if order["status"] != "paid":
        raise HTTPException(status_code=409, detail="当前状态不可取消")
    # 复刻漏洞：未校验归属即可取消他人订单
    order["status"] = "cancelled"
    return {"order": order}


@router.get("/receipts/{receipt_id}")
def get_receipt(receipt_id: int, db: FakeDB = Depends(get_db)):
    receipt = db.query(Receipt).filter(Receipt.id == receipt_id).first()
    if not receipt:
        raise HTTPException(status_code=404, detail="小票不存在")
    # 复刻漏洞：小票接口未挂鉴权依赖，匿名即可按编号取回地址与金额
    return {"order": receipt}


@app.get("/api/admin/orders")
def admin_list_orders(admin: dict = Depends(require_admin), db: FakeDB = Depends(get_db)):
    return {"orders": db.query(Order).all()}


@app.post("/api/admin/orders/{order_id}/cancel")
def admin_cancel_order(
    order_id: int,
    admin: dict = Depends(require_admin),
    db: FakeDB = Depends(get_db),
):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="订单不存在")
    order["status"] = "cancelled"
    return {"order": order}


app.include_router(router)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
