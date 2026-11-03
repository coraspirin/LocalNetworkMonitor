"""Uygulama yapılandırması.

Ortam değişkenleri yalnızca varsayılanları belirler; çalışma zamanında
değiştirilebilen ayarlar veritabanındaki ``Setting`` tablosunda tutulur
(bkz. ``app.settings_store``).
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    data_dir: Path = Path("/data")
    host: str = "0.0.0.0"
    port: int = 8080

    # Virgülle ayrılmış CIDR listesi; boşsa bağlı ağlar otomatik tespit edilir.
    subnets: str = ""

    quick_interval_min: int = 5
    deep_interval_hours: int = 24
    top_ports: int = 1000
    scan_concurrency: int = 4
    host_timeout_min: int = 10
    enable_vulners: bool = True
    enable_watchdog: bool = True
    dhcp_probe_interval_min: int = 60
    notify_on_leave: bool = False
    presence_retention_days: int = 30

    # Apprise URL'leri, virgül veya satır sonu ile ayrılmış
    # (ör. tgram://bottoken/chatid, mailtos://user:pass@gmail.com)
    apprise_urls: str = ""
    report_weekday: str = "mon"
    report_hour: int = 9

    # Arayüzde ve zamanlanmış işlerde kullanılan saat dilimi
    tz: str = "Europe/Istanbul"

    admin_password: str = ""
    secret_key: str = "change-me"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netscanner.db"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    return s
