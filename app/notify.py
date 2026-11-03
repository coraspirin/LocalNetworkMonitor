"""Apprise üzerinden bildirim gönderimi (Telegram, e-posta, Discord, ntfy, ...)."""

from __future__ import annotations

import logging
import threading

from app import settings_store

log = logging.getLogger(__name__)

SEVERITY_TO_APPRISE = {"info": "info", "low": "info", "medium": "warning", "high": "warning", "critical": "failure"}
SEVERITY_EMOJI = {"info": "ℹ️", "low": "🔵", "medium": "🟠", "high": "🔴", "critical": "🚨"}


def _build(urls: list[str]):
    import apprise

    ap = apprise.Apprise()
    for u in urls:
        ap.add(u)
    return ap


def send(title: str, body: str, severity: str = "info", html: bool = False, urls: list[str] | None = None, background: bool = True) -> bool:
    urls = urls if urls is not None else settings_store.apprise_url_list()
    if not urls:
        log.info("Bildirim (hedef yok): %s — %s", title, body)
        return False

    def _do() -> bool:
        import apprise

        try:
            ap = _build(urls)
            ok = ap.notify(
                title=f"{SEVERITY_EMOJI.get(severity, '')} {title}".strip(),
                body=body,
                notify_type=getattr(apprise.NotifyType, SEVERITY_TO_APPRISE.get(severity, "info").upper()),
                body_format=apprise.NotifyFormat.HTML if html else apprise.NotifyFormat.TEXT,
            )
            if not ok:
                log.warning("Bildirim gönderilemedi: %s", title)
            return bool(ok)
        except Exception:
            log.exception("Bildirim hatası")
            return False

    if background:
        threading.Thread(target=_do, daemon=True).start()
        return True
    return _do()


def send_batch(items: list[tuple[str, str, str]]) -> None:
    """Aynı taramada oluşan çok sayıda bildirimi tek mesajda toplar. items: (title, body, severity)"""
    if not items:
        return
    if len(items) == 1:
        send(*items[0])
        return
    from app.i18n import t

    worst = max(items, key=lambda i: ["info", "low", "medium", "high", "critical"].index(i[2]))[2]
    body = "\n".join(f"{SEVERITY_EMOJI.get(sev, '•')} {title}: {text}" for title, text, sev in items[:30])
    if len(items) > 30:
        body += "\n" + t("notify.more", n=len(items) - 30)
    send(t("notify.batch_title", n=len(items)), body, worst)
