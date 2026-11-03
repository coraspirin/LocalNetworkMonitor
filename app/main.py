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

from app import i18n, settings_store
from app.config import get_settings
from app.db import init_db
from app.scanner import devicetype

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("netscanner")

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
_TZ = ZoneInfo(get_settings().tz)

# Dile göre tarih biçimleri
DATE_FORMATS = {
    "tr": {"long": "%d.%m.%Y %H:%M", "short": "%d.%m %H:%M", "date": "%d.%m.%Y"},
    "en": {"long": "%b %d, %Y %H:%M", "short": "%b %d %H:%M", "date": "%b %d, %Y"},
}


def _localtime(value: datetime | str | None, fmt: str = "long") -> str:
    if value is None or value == "":
        return "—"
    fmt = DATE_FORMATS.get(i18n.get_lang(), DATE_FORMATS["tr"]).get(fmt, fmt)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_TZ).strftime(fmt)


templates.env.filters["localtime"] = _localtime
templates.env.filters["sev"] = lambda s: i18n.t(f"sev.{s}") if i18n.has(f"sev.{s}") else s
templates.env.globals["t"] = i18n.t
templates.env.globals["get_lang"] = i18n.get_lang
templates.env.globals["js_catalog"] = lambda: i18n.js_catalog(i18n.get_lang())
templates.env.globals["finding_text"] = i18n.finding_text
templates.env.globals["event_text"] = i18n.event_text
templates.env.globals["diff_text"] = i18n.diff_text
templates.env.globals["change_name"] = i18n.change_name
templates.env.globals["type_icon"] = devicetype.icon
templates.env.globals["type_label"] = devicetype.label
templates.env.globals["DEVICE_TYPES"] = devicetype.TYPES


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

PUBLIC_PATHS = ("/login", "/static/", "/api/health", "/lang/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    lang = i18n.pick_lang(request.cookies.get("lang"), request.headers.get("accept-language"), i18n.default_language())
    i18n.set_lang(lang)
    request.state.lang = lang
    password = get_settings().admin_password
    if password and not request.url.path.startswith(PUBLIC_PATHS) and not request.session.get("auth"):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": i18n.t("err.login_required")}, status_code=401)
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
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": i18n.t("login.error")}, status_code=401)


@app.get("/lang/{code}")
def set_language(code: str, next: str = "/"):
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    if code in i18n.LANGS:
        resp.set_cookie("lang", code, max_age=60 * 60 * 24 * 365, samesite="lax")
    return resp


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
