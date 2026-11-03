"""FastAPI uygulaması: başlatma, kimlik doğrulama, sayfa ve API yönlendiricileri."""

from __future__ import annotations

import hmac
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import settings_store
from app.config import get_settings
from app.db import init_db
from app.scanner import devicetype

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("netscanner")

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
_TZ = ZoneInfo(get_settings().tz)

SEVERITY_LABELS = {"info": "Bilgi", "low": "Düşük", "medium": "Orta", "high": "Yüksek", "critical": "Kritik"}


def _localtime(value: datetime | str | None, fmt: str = "%d.%m.%Y %H:%M") -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_TZ).strftime(fmt)


templates.env.filters["localtime"] = _localtime
templates.env.filters["sev"] = lambda s: SEVERITY_LABELS.get(s, s)
templates.env.globals["type_icon"] = devicetype.icon
templates.env.globals["type_label"] = devicetype.label
templates.env.globals["DEVICE_TYPES"] = devicetype.TYPES
templates.env.globals["SEVERITY_LABELS"] = SEVERITY_LABELS


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app import scheduler
    from app.monitor import watchdog_service

    init_db()
    settings_store.ensure_subnets()
    if os.environ.get("NETSCANNER_DISABLE_BACKGROUND") != "1":
        scheduler.start(templates.env, run_initial=os.environ.get("NETSCANNER_SKIP_INITIAL_SCAN") != "1")
        if settings_store.get("enable_watchdog"):
            watchdog_service.start()
    log.info("Ağ izleyici hazır: http://%s:%s", get_settings().host, get_settings().port)
    yield
    scheduler.shutdown()
    watchdog_service.stop()


app = FastAPI(title="Local Network Monitor", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")

PUBLIC_PATHS = ("/login", "/static/", "/api/health")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    password = get_settings().admin_password
    if password and not request.url.path.startswith(PUBLIC_PATHS) and not request.session.get("auth"):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Giriş gerekli"}, status_code=401)
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
    return await call_next(request)


# SessionMiddleware, auth_middleware'den sonra eklenir ki önce o çalışsın (request.session hazır olsun)
app.add_middleware(SessionMiddleware, secret_key=get_settings().secret_key, same_site="lax", max_age=60 * 60 * 24 * 30)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": None})


@app.post("/login")
def login(request: Request, password: str = Form(...), next: str = Form("/")):
    expected = get_settings().admin_password
    if expected and hmac.compare_digest(password.encode(), expected.encode()):
        request.session["auth"] = True
        target = next if next.startswith("/") and not next.startswith("//") else "/"
        return RedirectResponse(target, status_code=303)
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": "Hatalı şifre"}, status_code=401)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


from app import api, web  # noqa: E402

app.include_router(api.router)
app.include_router(web.router)


def run() -> None:  # pragma: no cover
    import uvicorn

    s = get_settings()
    uvicorn.run("app.main:app", host=s.host, port=s.port, proxy_headers=True)


if __name__ == "__main__":  # pragma: no cover
    run()
