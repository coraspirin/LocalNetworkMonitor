"""Hafif, bağımlılıksız çok dillilik (Türkçe / İngilizce).

Etkin dil bir ``ContextVar`` içinde tutulur: web isteklerinde middleware, arka plan
işlerinde (bildirim, rapor) ``use_lang`` ile ayarlanır.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

LANGS = ("tr", "en")
DEFAULT_LANG = "tr"
_lang: ContextVar[str] = ContextVar("lang", default=DEFAULT_LANG)

# anahtar -> (Türkçe, İngilizce)
M: dict[str, tuple[str, str]] = {
    # ------------------------------------------------------------ genel
    "app.name": ("Ağ İzleyici", "Network Monitor"),
    "common.network_wide": ("Ağ geneli", "Network-wide"),
    "common.network": ("Ağ", "Network"),
    "common.device": ("Cihaz", "Device"),
    "common.deleted_device": ("Silinmiş cihaz", "Deleted device"),
    "common.none": ("—", "—"),
    "common.save": ("Kaydet", "Save"),
    "common.delete": ("Sil", "Delete"),
    "common.add": ("Ekle", "Add"),
    "common.confirm": ("Onayla", "Confirm"),
    "common.online": ("Çevrimiçi", "Online"),
    "common.offline": ("Çevrimdışı", "Offline"),
    "common.all": ("Tümü", "All"),
    "common.yes": ("Evet", "Yes"),
    "common.no": ("Hayır", "No"),
    "common.port": ("port {port}", "port {port}"),
    "common.now": ("şimdi", "now"),
    "common.language": ("Dil", "Language"),
    "common.open_new_tab": ("Yeni sekmede aç", "Open in new tab"),
    "common.loading": ("Yükleniyor…", "Loading…"),
    "common.gateway": ("ağ geçidi", "gateway"),
    "common.new": ("yeni", "new"),
    "common.hidden_mac": ("gizli", "private"),
    "common.trusted": ("güvenilir", "trusted"),
    "common.all_history": ("Tüm geçmiş →", "Full history →"),
    "common.source": ("kaynak", "source"),
    "common.first_seen_at": ("İlk görülme {ts}", "First seen {ts}"),
    "common.last_seen_at": ("Son görülme {ts}", "Last seen {ts}"),
    # ------------------------------------------------------------ menü
    "nav.devices": ("Cihazlar", "Devices"),
    "nav.map": ("Harita", "Map"),
    "nav.security": ("Güvenlik", "Security"),
    "nav.history": ("Geçmiş", "History"),
    "nav.report": ("Rapor", "Report"),
    "nav.settings": ("Ayarlar", "Settings"),
    "nav.quick_scan": ("Hızlı keşif", "Quick scan"),
    "nav.quick_scan_tip": ("ARP/ping ile cihazları bul", "Find devices via ARP/ping"),
    "nav.deep_scan": ("Derin tara", "Deep scan"),
    "nav.deep_scan_tip": ("Port, servis, OS ve güvenlik taraması", "Port, service, OS and security scan"),
    "nav.logout": ("Çıkış", "Log out"),
    # ------------------------------------------------------------ önem
    "sev.info": ("Bilgi", "Info"),
    "sev.low": ("Düşük", "Low"),
    "sev.medium": ("Orta", "Medium"),
    "sev.high": ("Yüksek", "High"),
    "sev.critical": ("Kritik", "Critical"),
    # ------------------------------------------------------------ cihaz tipleri
    "type.router": ("Router / Ağ cihazı", "Router / Network device"),
    "type.phone": ("Telefon / Tablet", "Phone / Tablet"),
    "type.computer": ("Bilgisayar", "Computer"),
    "type.printer": ("Yazıcı", "Printer"),
    "type.tv": ("TV / Medya oynatıcı", "TV / Media player"),
    "type.speaker": ("Hoparlör", "Speaker"),
    "type.camera": ("Kamera", "Camera"),
    "type.nas": ("NAS / Sunucu", "NAS / Server"),
    "type.gaming": ("Oyun konsolu", "Game console"),
    "type.iot": ("Akıllı ev / IoT", "Smart home / IoT"),
    "type.unknown": ("Bilinmiyor", "Unknown"),
    # ------------------------------------------------------------ OS ailesi (DHCP parmak izi)
    "os.apple": ("Apple (iOS/macOS)", "Apple (iOS/macOS)"),
    "os.android": ("Android", "Android"),
    "os.windows": ("Windows", "Windows"),
    "os.linux": ("Linux", "Linux"),
    "os.embedded": ("Gömülü / IoT Linux", "Embedded / IoT Linux"),
    # ------------------------------------------------------------ giriş
    "login.title": ("Giriş", "Sign in"),
    "login.prompt": ("Devam etmek için yönetici şifresini girin.", "Enter the admin password to continue."),
    "login.password": ("Şifre", "Password"),
    "login.submit": ("Giriş yap", "Sign in"),
    "login.error": ("Hatalı şifre", "Wrong password"),
    # ------------------------------------------------------------ pano
    "dash.title": ("Cihazlar", "Devices"),
    "dash.heading": ("Ağdaki cihazlar", "Devices on the network"),
    "dash.last_deep": ("Son derin tarama: {ts}", "Last deep scan: {ts}"),
    "dash.no_deep": ("Henüz derin tarama yapılmadı — sağ üstten “Derin tara” ile başlatın.", "No deep scan yet — start one with “Deep scan” at the top right."),
    "dash.csv": ("CSV indir", "Download CSV"),
    "dash.json": ("JSON indir", "Download JSON"),
    "dash.total": ("Toplam cihaz", "Total devices"),
    "dash.new_24h": ("{n} yeni (son 24 saat)", "{n} new (last 24 h)"),
    "dash.online": ("Çevrimiçi", "Online"),
    "dash.offline_n": ("{n} çevrimdışı", "{n} offline"),
    "dash.score": ("Güvenlik skoru", "Security score"),
    "dash.open_findings": ("Açık bulgular", "Open findings"),
    "dash.no_findings": ("Bulgu yok", "No findings"),
    "dash.search": ("Ara: ad, IP, MAC, üretici…", "Search: name, IP, MAC, vendor…"),
    "dash.all_subnets": ("Tüm ağlar", "All networks"),
    "dash.f_online": ("Çevrimiçi", "Online"),
    "dash.f_offline": ("Çevrimdışı", "Offline"),
    "dash.f_untrusted": ("Güvenilmeyen", "Untrusted"),
    "dash.f_risk": ("Riskli", "At risk"),
    "dash.f_suggest": ("Bekleyen eşleşmeler", "Pending matches"),
    "dash.f_archived": ("Arşivlenmiş", "Archived"),
    "dash.col_device": ("Cihaz", "Device"),
    "dash.col_ip": ("IP", "IP"),
    "dash.col_mac": ("MAC", "MAC"),
    "dash.col_vendor": ("Üretici", "Vendor"),
    "dash.col_ports": ("Port", "Ports"),
    "dash.col_risk": ("Risk", "Risk"),
    "dash.col_last_seen": ("Son görülme", "Last seen"),
    "dash.untrusted_tip": ("Henüz güvenilir olarak işaretlenmedi", "Not marked as trusted yet"),
    "dash.hidden_mac_tip": ("Gizli / rastgele MAC adresi", "Private / randomized MAC address"),
    "dash.match_badge": ("eşleşme?", "match?"),
    "dash.match_tip": ("Bilinen bir cihazın yeni MAC adresi olabilir", "May be a known device's new MAC address"),
    "dash.no_match": ("Filtreye uyan cihaz yok.", "No devices match the filter."),
    "dash.empty": ("Henüz cihaz bulunmadı. İlk tarama birkaç saniye içinde başlar; dilerseniz “Hızlı keşif” düğmesini kullanın.",
                   "No devices found yet. The first scan starts within seconds; you can also press “Quick scan”."),
    "dash.recent": ("Son olaylar", "Recent events"),
    "dash.no_events": ("Henüz olay yok.", "No events yet."),
    # ------------------------------------------------------------ cihaz sayfası
    "dev.trust": ("✓ Güvenilir olarak işaretle", "✓ Mark as trusted"),
    "dev.untrust": ("Güvenilir işaretini kaldır", "Remove trusted mark"),
    "dev.general": ("Genel bilgiler", "Overview"),
    "dev.type": ("Tip", "Type"),
    "dev.os": ("İşletim sistemi", "Operating system"),
    "dev.os_family": ("DHCP parmak izi", "DHCP fingerprint"),
    "dev.hostname": ("Hostname (DNS)", "Hostname (DNS)"),
    "dev.dhcp_hostname": ("DHCP adı", "DHCP name"),
    "dev.mdns_name": ("mDNS adı", "mDNS name"),
    "dev.netbios_name": ("NetBIOS adı", "NetBIOS name"),
    "dev.subnet": ("Ağ", "Network"),
    "dev.mac_kind": ("MAC türü", "MAC type"),
    "dev.mac_random": ("Gizli / rastgele (locally administered)", "Private / randomized (locally administered)"),
    "dev.mac_hw": ("Donanım (üretici atanmış)", "Hardware (vendor assigned)"),
    "dev.latency": ("Gecikme", "Latency"),
    "dev.first_seen": ("İlk görülme", "First seen"),
    "dev.last_seen": ("Son görülme", "Last seen"),
    "dev.last_deep": ("Son derin tarama", "Last deep scan"),
    "dev.inventory": ("Envanter", "Inventory"),
    "dev.name": ("Ad", "Name"),
    "dev.location": ("Konum", "Location"),
    "dev.location_ph": ("ör. Salon", "e.g. Living room"),
    "dev.owner": ("Sahibi", "Owner"),
    "dev.notes": ("Notlar", "Notes"),
    "dev.timeline": ("Çevrimiçi zaman çizelgesi", "Online timeline"),
    "dev.uptime_summary": ("Son 24 saat: {d1}% çevrimiçi · Son 7 gün: {d7}% · Ort. gecikme: {avg}",
                           "Last 24 h: {d1}% online · Last 7 days: {d7}% · Avg. latency: {avg}"),
    "dev.rtt_max": ("(en yüksek {v} ms)", "(max {v} ms)"),
    "dev.last_24h": ("Son 24 saat", "Last 24 hours"),
    "dev.last_7d": ("Son 7 gün", "Last 7 days"),
    "dev.ago_24h": ("24 saat önce", "24 hours ago"),
    "dev.ago_7d": ("7 gün önce", "7 days ago"),
    "dev.timeline_help": ("Yeşil: görüldü · Gri: görülmedi · Boş: tarama yapılmadı. Telefonlar uyku modunda ARP'ye yanıt vermeyebilir.",
                          "Green: seen · Grey: not seen · Empty: no scan. Phones may not answer ARP while asleep."),
    "dev.ports": ("Açık portlar ve servisler", "Open ports and services"),
    "dev.col_port": ("Port", "Port"),
    "dev.col_service": ("Servis", "Service"),
    "dev.col_product": ("Ürün / sürüm", "Product / version"),
    "dev.no_ports": ("Açık port bulunamadı.", "No open ports found."),
    "dev.not_deep": ("Bu cihaz henüz derin taramadan geçmedi.", "This device has not been deep scanned yet."),
    "dev.findings": ("Güvenlik bulguları", "Security findings"),
    "dev.no_findings": ("Aktif bulgu yok.", "No active findings."),
    "dev.no_findings_not_deep": ("Aktif bulgu yok (cihaz henüz derin taranmadı).", "No active findings (device not deep scanned yet)."),
    "dev.resolved": ("Çözülmüş bulgular ({n})", "Resolved findings ({n})"),
    "dev.announce": ("Kendini tanıtma bilgileri", "Self-announced information"),
    "dev.mdns": ("mDNS / Bonjour servisleri", "mDNS / Bonjour services"),
    "dev.no_mdns": ("Yayın yok.", "No announcements."),
    "dev.ssdp": ("SSDP / UPnP", "SSDP / UPnP"),
    "dev.no_ssdp": ("Yanıt yok.", "No response."),
    "dev.macs": ("MAC adresleri", "MAC addresses"),
    "dev.macs_help": ("Gizli MAC kullanan telefonlar zamanla farklı adresler alır; aynı cihaza ait adresler burada toplanır.",
                      "Phones using private MACs get new addresses over time; addresses of the same device are collected here."),
    "dev.col_first": ("İlk", "First"),
    "dev.col_last": ("Son", "Last"),
    "dev.split": ("Ayır", "Split"),
    "dev.no_macs": ("Kayıtlı MAC yok (yönlendirilmiş ağ).", "No MAC recorded (routed network)."),
    "dev.merge_title": ("Başka bir kayıtla birleştir", "Merge with another record"),
    "dev.merge_pick": ("Bu kaydı şu cihaza taşı…", "Move this record into…"),
    "dev.merge_btn": ("Birleştir", "Merge"),
    "dev.offline_suffix": (" — çevrimdışı", " — offline"),
    "dev.events": ("Olay geçmişi", "Event history"),
    "dev.no_events": ("Olay yok.", "No events."),
    "dev.ios_tip_title": ("Bu cihaz gizli (rastgele) MAC kullanıyor", "This device uses a private (randomized) MAC"),
    "dev.ios_tip": ("MAC adresi değiştikçe yeni cihaz gibi görünebilir. En güvenilir çözüm: iPhone/iPad'de Ayarlar → Wi‑Fi → (ev ağı) ⓘ → Özel Wi‑Fi Adresi → “Sabit”; Android'de Wi‑Fi ağ ayarları → Gizlilik → “Cihaz MAC'ini kullan”. Böylece adres bu ağ için kalıcı olur.",
                    "It may look like a new device whenever its MAC changes. Most reliable fix: on iPhone/iPad go to Settings → Wi‑Fi → (home network) ⓘ → Private Wi‑Fi Address → “Fixed”; on Android Wi‑Fi network settings → Privacy → “Use device MAC”. The address then stays constant on this network."),
    "dev.suggest_title": ("Olası eşleşme", "Possible match"),
    "dev.suggest_text": ("Bu kayıt, {name} cihazının yeni MAC adresi olabilir (benzerlik skoru {score}).",
                         "This record may be the new MAC address of {name} (similarity score {score})."),
    "dev.suggest_text_rev": ("{name} kaydı bu cihazın yeni MAC adresi olabilir (benzerlik skoru {score}).",
                             "The record {name} may be this device's new MAC address (similarity score {score})."),
    "dev.suggest_reasons": ("Nedenler: {reasons}", "Reasons: {reasons}"),
    "dev.suggest_accept": ("Aynı cihaz — birleştir", "Same device — merge"),
    "dev.suggest_reject": ("Farklı cihaz", "Different device"),
    "dev.archived_badge": ("arşivlendi", "archived"),
    # ------------------------------------------------------------ eşleşme nedenleri
    "reason.name": ("aynı cihaz adı", "same device name"),
    "reason.dhcp_fp": ("aynı DHCP parmak izi", "same DHCP fingerprint"),
    "reason.ports": ("aynı açık portlar", "same open ports"),
    "reason.os_family": ("aynı işletim sistemi ailesi", "same OS family"),
    "reason.type": ("aynı cihaz tipi", "same device type"),
    "reason.timing": ("eski adres yeni adres görülmeden kısa süre önce kayboldu", "the old address vanished shortly before the new one appeared"),
    # ------------------------------------------------------------ bulgu kartı
    "finding.ignore": ("Yoksay", "Ignore"),
    "finding.unignore": ("Geri al", "Undo"),
    "finding.resolve": ("Çözüldü", "Resolved"),
    "finding.ignored": ("yoksayıldı", "ignored"),
    "finding.fix": ("Öneri:", "Recommendation:"),
    "finding.reopened": ("Tekrar görüldü: {title}", "Seen again: {title}"),
    # ------------------------------------------------------------ güvenlik sayfası
    "sec.title": ("Güvenlik", "Security"),
    "sec.subtitle": ("Derin taramalar, router denetimi ve sürekli izleme bulguları", "Findings from deep scans, router audit and continuous monitoring"),
    "sec.score_help": ("{label} — açık bulgulara göre hesaplanır (kritik −25, yüksek −10, orta −4, düşük −1; cihaz başına en fazla −40).",
                       "{label} — based on open findings (critical −25, high −10, medium −4, low −1; at most −40 per device)."),
    "sec.history": ("Skor geçmişi (60 gün)", "Score history (60 days)"),
    "sec.history_empty": ("İlk derin taramadan sonra burada görünecek.", "Appears here after the first deep scan."),
    "sec.distribution": ("Bulgu dağılımı", "Findings by severity"),
    "sec.open": ("Açık bulgular", "Open findings"),
    "sec.none": ("🎉 Açık bulgu yok.", "🎉 No open findings."),
    "sec.router": ("Router / UPnP", "Router / UPnP"),
    "sec.router_never": ("Henüz denetlenmedi (derin taramada çalışır).", "Not audited yet (runs during deep scans)."),
    "sec.router_off": ("✅ UPnP IGD yanıt vermedi — router'da UPnP kapalı görünüyor.", "✅ No UPnP IGD answered — UPnP appears to be disabled on the router."),
    "sec.last_check": ("Son kontrol", "Last check"),
    "sec.router_model": ("Router", "Router"),
    "sec.external_ip": ("Dış IP", "External IP"),
    "sec.mappings": ("UPnP port yönlendirmeleri ({n})", "UPnP port forwards ({n})"),
    "sec.col_external": ("Dış", "External"),
    "sec.col_internal": ("İç hedef", "Internal target"),
    "sec.col_desc": ("Açıklama", "Description"),
    "sec.no_mappings": ("Yönlendirme yok.", "No port forwards."),
    "sec.watch": ("Sürekli izleme", "Continuous monitoring"),
    "sec.arp_watch": ("ARP izleyici", "ARP watcher"),
    "sec.running": ("🟢 çalışıyor", "🟢 running"),
    "sec.stopped": ("⚪ kapalı", "⚪ off"),
    "sec.gw_mac": ("Ağ geçidi MAC", "Gateway MAC"),
    "sec.dhcp_known": ("Bilinen DHCP", "Known DHCP"),
    "sec.last_probe": ("Son DHCP yoklaması", "Last DHCP probe"),
    "sec.offers": ("{n} teklif", "{n} offers"),
    "sec.probe_btn": ("DHCP sunucularını şimdi kontrol et", "Check DHCP servers now"),
    "sec.watch_help": ("ARP izleyici, ağ geçidinin MAC adresinin değişmesini (ARP spoofing) anında yakalar. DHCP yoklaması ağda ikinci bir DHCP sunucusu olup olmadığını kontrol eder. İzleyici ayrıca cihazların DHCP isteklerinden ad ve işletim sistemi parmak izi toplar.",
                       "The ARP watcher instantly detects a change of the gateway's MAC address (ARP spoofing). The DHCP probe checks for a second DHCP server. The watcher also collects device names and OS fingerprints from DHCP requests."),
    # ------------------------------------------------------------ geçmiş
    "hist.title": ("Geçmiş", "History"),
    "hist.subtitle": ("Taramalar ve ağ olayları", "Scans and network events"),
    "hist.compare": ("Taramaları karşılaştır →", "Compare scans →"),
    "hist.timeline": ("Olay zaman çizelgesi", "Event timeline"),
    "hist.all_events": ("Tüm olaylar", "All events"),
    "hist.scans": ("Taramalar", "Scans"),
    "hist.col_time": ("Zaman", "Time"),
    "hist.col_kind": ("Tür", "Type"),
    "hist.col_hosts": ("Host", "Hosts"),
    "hist.deep": ("Derin", "Deep"),
    "hist.quick": ("Hızlı", "Quick"),
    "hist.failed": ("hata", "failed"),
    "hist.running": ("sürüyor", "running"),
    "hist.n_changes": ("{n} fark", "{n} changes"),
    "hist.no_scans": ("Tarama yok.", "No scans."),
    # ------------------------------------------------------------ olay türleri (etiket)
    "evk.joined": ("Yeni cihaz", "New device"),
    "evk.joined_maybe_known": ("Yeni MAC", "New MAC"),
    "evk.left": ("Ayrıldı", "Left"),
    "evk.returned": ("Geri döndü", "Returned"),
    "evk.ip_changed": ("IP değişti", "IP changed"),
    "evk.port_opened": ("Port açıldı", "Port opened"),
    "evk.port_closed": ("Port kapandı", "Port closed"),
    "evk.finding": ("Bulgu", "Finding"),
    "evk.arp_spoof": ("ARP spoofing", "ARP spoofing"),
    "evk.rogue_dhcp": ("Sahte DHCP", "Rogue DHCP"),
    "evk.merged": ("Birleştirildi", "Merged"),
    "evk.ip_mac_changed": ("IP/MAC değişti", "IP/MAC changed"),
    "evk.archived": ("Arşivlendi", "Archived"),
    # ------------------------------------------------------------ olay mesajları
    "ev.joined": ("Yeni cihaz: {ip} / {mac} ({vendor})", "New device: {ip} / {mac} ({vendor})"),
    "ev.joined_maybe_known": ("Yeni gizli MAC ({mac}, {ip}) — muhtemelen {candidate} (skor {score})",
                              "New private MAC ({mac}, {ip}) — probably {candidate} (score {score})"),
    "ev.random_mac": ("Gizli (rastgele) MAC", "Private (random) MAC"),
    "ev.unknown_vendor": ("bilinmeyen üretici", "unknown vendor"),
    "ev.no_mac": ("MAC yok", "no MAC"),
    "ev.left": ("Ağdan ayrıldı ({ip})", "Left the network ({ip})"),
    "ev.returned": ("Ağa geri döndü ({ip})", "Back on the network ({ip})"),
    "ev.ip_changed": ("IP değişti: {old} → {new}", "IP changed: {old} → {new}"),
    "ev.merged": ("{mac} adresli kayıt bu cihazla birleştirildi", "Record {mac} was merged into this device"),
    "ev.merged_auto": ("Yeni gizli MAC ({mac}) bu cihaza bağlandı", "New private MAC ({mac}) linked to this device"),
    "ev.merged_auto_score": ("Yeni gizli MAC ({mac}) bu cihaza bağlandı (skor {score})", "New private MAC ({mac}) linked to this device (score {score})"),
    "ev.port_opened": ("{port} açıldı: {service}", "{port} opened: {service}"),
    "ev.port_closed": ("{port} kapandı", "{port} closed"),
    "ev.ip_mac_changed": ("{ip} adresinin MAC'i değişti: {old} → {new}", "MAC of {ip} changed: {old} → {new}"),
    "ev.archived": ("30 gündür görülmediği için arşivlendi", "Archived after not being seen for 30 days"),
    "ev.arp_spoof": ("Ağ geçidi ({ip}) için farklı bir MAC adresi yayınlandı: {mac} (beklenen {expected}). Olası ARP spoofing / ortadaki adam saldırısı.",
                     "A different MAC address was announced for the gateway ({ip}): {mac} (expected {expected}). Possible ARP spoofing / man-in-the-middle attack."),
    "ev.rogue_dhcp_multi": ("Ağda birden fazla DHCP sunucusu yanıt verdi: {servers}. Sahte bir DHCP sunucusu trafiği yönlendirebilir.",
                            "More than one DHCP server answered: {servers}. A rogue DHCP server can redirect traffic."),
    "ev.rogue_dhcp_unexpected": ("Beklenmeyen DHCP sunucusu: {server} (beklenen {expected}).", "Unexpected DHCP server: {server} (expected {expected})."),
    # ------------------------------------------------------------ diff
    "diff.title": ("Tarama karşılaştırma", "Scan comparison"),
    "diff.subtitle": ("İki derin tarama arasındaki port, servis, işletim sistemi ve bulgu farkları", "Port, service, OS and finding differences between two deep scans"),
    "diff.need_two": ("Karşılaştırma için en az iki tamamlanmış derin tarama gerekiyor ({n} mevcut).", "At least two completed deep scans are needed ({n} available)."),
    "diff.older": ("Eski", "Older"),
    "diff.newer": ("Yeni", "Newer"),
    "diff.compare": ("Karşılaştır", "Compare"),
    "diff.col_device": ("Cihaz", "Device"),
    "diff.col_change": ("Değişiklik", "Change"),
    "diff.col_detail": ("Ayrıntı", "Detail"),
    "diff.none": ("Bu iki tarama arasında fark yok.", "No differences between these two scans."),
    "diffk.device_added": ("Yeni cihaz", "New device"),
    "diffk.device_missing": ("Bulunamadı", "Not found"),
    "diffk.port_opened": ("Port açıldı", "Port opened"),
    "diffk.port_closed": ("Port kapandı", "Port closed"),
    "diffk.service_changed": ("Servis değişti", "Service changed"),
    "diffk.os_changed": ("OS değişti", "OS changed"),
    "diffk.ip_changed": ("IP değişti", "IP changed"),
    "diffk.finding_new": ("Yeni bulgu", "New finding"),
    "diffk.finding_resolved": ("Bulgu çözüldü", "Finding resolved"),
    "diffd.device_added": ("Yeni cihaz ({ip})", "New device ({ip})"),
    "diffd.device_missing": ("Bu taramada bulunamadı (son IP {ip})", "Not found in this scan (last IP {ip})"),
    "diffd.port_opened": ("{port} açıldı: {service}", "{port} opened: {service}"),
    "diffd.port_closed": ("{port} kapandı", "{port} closed"),
    "diffd.service_changed": ("{port}: {old} → {new}", "{port}: {old} → {new}"),
    "diffd.os_changed": ("{old} → {new}", "{old} → {new}"),
    "diffd.ip_changed": ("{old} → {new}", "{old} → {new}"),
    # ------------------------------------------------------------ harita
    "map.title": ("Ağ haritası", "Network map"),
    "map.subtitle": ("Ağ geçidi merkezde; cihazlar ağa (subnet) ve tipe göre gruplanır. Bir cihaza tıklayarak ayrıntılara gidin.",
                     "Gateway in the center; devices grouped by network (subnet) and type. Click a device for details."),
    "map.show_offline": ("Çevrimdışıları göster", "Show offline"),
    "map.mid_risk": ("◯ orta risk", "◯ medium risk"),
    "map.high_risk": ("◯ yüksek/kritik risk", "◯ high/critical risk"),
    # ------------------------------------------------------------ ayarlar
    "set.title": ("Ayarlar", "Settings"),
    "set.subtitle": ("Değişiklikler hemen uygulanır; zamanlayıcı yeniden yapılandırılır.", "Changes apply immediately; the scheduler is reconfigured."),
    "set.subnets": ("Taranan ağlar", "Scanned networks"),
    "set.subnets_help": ("Doğrudan bağlı ağlarda ARP kullanılır (MAC ve üretici bilgisi alınır). Router arkasındaki VLAN'larda ping taraması yapılır; bu ağlarda MAC/üretici görünmez.",
                         "Directly connected networks are scanned with ARP (MAC and vendor available). VLANs behind a router are ping-scanned; MAC/vendor is not visible there."),
    "set.col_label": ("Etiket", "Label"),
    "set.col_cidr": ("CIDR", "CIDR"),
    "set.col_mode": ("Yöntem", "Method"),
    "set.col_enabled": ("Aktif", "Enabled"),
    "set.mode_auto": ("Otomatik", "Automatic"),
    "set.mode_arp": ("ARP", "ARP"),
    "set.mode_ping": ("Ping", "Ping"),
    "set.no_subnets": ("Ağ tanımlı değil. Otomatik tespit başarısız olduysa aşağıdan ekleyin.", "No networks defined. Add one below if auto-detection failed."),
    "set.add_subnet": ("Ağ ekle", "Add network"),
    "set.label_ph": ("Etiket (ör. IoT)", "Label (e.g. IoT)"),
    "set.schedule": ("Zamanlama", "Scheduling"),
    "set.quick_interval": ("Hızlı keşif aralığı (dakika)", "Quick scan interval (minutes)"),
    "set.deep_interval": ("Derin tarama aralığı (saat, 0 = kapalı)", "Deep scan interval (hours, 0 = off)"),
    "set.top_ports": ("Taranacak port sayısı (en yaygın N)", "Ports to scan (top N)"),
    "set.concurrency": ("Aynı anda taranan cihaz", "Devices scanned in parallel"),
    "set.host_timeout": ("Cihaz başına zaman aşımı (dakika)", "Per-device timeout (minutes)"),
    "set.retention": ("Varlık geçmişi saklama (gün)", "Presence history retention (days)"),
    "set.vulners": ("CVE zafiyet kontrolü (vulners — internet bağlantısı gerekir)", "CVE vulnerability check (vulners — needs internet access)"),
    "set.next_runs": ("Sonraki çalışmalar", "Next runs"),
    "set.no_scheduler": ("Zamanlayıcı çalışmıyor", "Scheduler not running"),
    "set.job.quick": ("Hızlı keşif", "Quick scan"),
    "set.job.deep": ("Derin tarama", "Deep scan"),
    "set.job.dhcp": ("DHCP yoklaması", "DHCP probe"),
    "set.job.weekly_report": ("Haftalık rapor", "Weekly report"),
    "set.job.cleanup": ("Temizlik", "Cleanup"),
    "set.job.initial": ("İlk tarama", "Initial scan"),
    "set.notifications": ("Bildirimler", "Notifications"),
    "set.apprise": ("Bildirim adresleri (her satıra bir tane,", "Notification URLs (one per line,"),
    "set.apprise_link": ("Apprise formatı", "Apprise format"),
    "set.notify_leave": ("Cihaz ağdan ayrıldığında da bildir", "Also notify when a device leaves"),
    "set.random_notify": ("Gizli MAC'li yeni cihazlar için bildirim", "Notifications for new private-MAC devices"),
    "set.random_smart": ("Akıllı: önce eşleştirmeyi dene, bilinen cihazsa sessiz kal", "Smart: try matching first, stay quiet for known devices"),
    "set.random_always": ("Her zaman hemen bildir", "Always notify immediately"),
    "set.random_never": ("Hiç bildirme", "Never notify"),
    "set.report_day": ("Haftalık rapor günü", "Weekly report day"),
    "set.report_hour": ("Rapor saati", "Report hour"),
    "set.test_notify": ("Test bildirimi gönder", "Send test notification"),
    "set.notify_help": ("Bildirim gönderilen olaylar: yeni (güvenilmeyen) cihaz, yeni açılan port, yüksek/kritik güvenlik bulgusu, ARP spoofing, sahte DHCP sunucusu.",
                        "Notified events: new (untrusted) device, newly opened port, high/critical finding, ARP spoofing, rogue DHCP server."),
    "set.general": ("Genel", "General"),
    "set.default_lang": ("Varsayılan dil (bildirimler, rapor ve yeni ziyaretçiler)", "Default language (notifications, report and new visitors)"),
    "set.watch": ("Sürekli izleme", "Continuous monitoring"),
    "set.watch_enable": ("ARP spoofing izleyicisini çalıştır (DHCP parmak izi toplama dahil)", "Run the ARP spoofing watcher (incl. DHCP fingerprinting)"),
    "set.dhcp_interval": ("DHCP yoklama aralığı (dakika, 0 = kapalı)", "DHCP probe interval (minutes, 0 = off)"),
    "set.known": ("Bilinen değerler", "Known values"),
    "set.known_help": ("Router'ı değiştirdiyseniz yeni değerleri onaylayın; aksi halde sahte uyarı alırsınız.", "If you replaced your router, confirm the new values; otherwise you'll get false alarms."),
    "set.gw_mac": ("Ağ geçidi MAC", "Gateway MAC"),
    "set.dhcp_server": ("DHCP sunucusu", "DHCP server"),
    "day.mon": ("Pazartesi", "Monday"),
    "day.tue": ("Salı", "Tuesday"),
    "day.wed": ("Çarşamba", "Wednesday"),
    "day.thu": ("Perşembe", "Thursday"),
    "day.fri": ("Cuma", "Friday"),
    "day.sat": ("Cumartesi", "Saturday"),
    "day.sun": ("Pazar", "Sunday"),
    # ------------------------------------------------------------ rapor
    "rep.title": ("Haftalık rapor", "Weekly report"),
    "rep.subtitle": ("Ayarlarda seçilen gün ve saatte bildirim adreslerine otomatik gönderilir. Önizleme, varsayılan dilde ({lang}) gösterilir.",
                     "Sent automatically to the notification URLs on the configured day and hour. The preview uses the default language ({lang})."),
    "rep.send": ("Şimdi gönder", "Send now"),
    "rep.need_target": ("Rapor göndermek için Ayarlar sayfasından bir bildirim adresi (ör. e-posta) ekleyin.", "To send the report, add a notification URL (e.g. e-mail) on the Settings page."),
    "rep.preview": ("Rapor önizlemesi", "Report preview"),
    "mail.title": ("Haftalık ağ raporu", "Weekly network report"),
    "mail.period": ("Son {days} gün · {ts}", "Last {days} days · {ts}"),
    "mail.score": ("Güvenlik skoru", "Security score"),
    "mail.prev": ("geçen hafta {v}", "last week {v}"),
    "mail.devices": ("Cihazlar", "Devices"),
    "mail.online_n": ("{n} çevrimiçi", "{n} online"),
    "mail.new_devices": ("Yeni cihaz", "New devices"),
    "mail.left_n": ("{n} ayrılma olayı", "{n} departures"),
    "mail.alerts": ("⚠️ Güvenlik uyarıları", "⚠️ Security alerts"),
    "mail.new_devices_h": ("Yeni cihazlar", "New devices"),
    "mail.no_new_devices": ("Bu hafta yeni cihaz katılmadı.", "No new devices joined this week."),
    "mail.new_findings_h": ("Bu hafta ortaya çıkan bulgular", "Findings that appeared this week"),
    "mail.resolved": ("(çözüldü)", "(resolved)"),
    "mail.no_new_findings": ("Yeni bulgu yok. 🎉", "No new findings. 🎉"),
    "mail.open_h": ("Açık bulgular (en önemli 20)", "Open findings (top 20)"),
    "mail.no_open": ("Açık bulgu yok.", "No open findings."),
    "mail.left_h": ("Ağdan ayrılanlar", "Devices that left"),
    "mail.footer": ("Local Network Monitor tarafından otomatik oluşturuldu.", "Generated automatically by Local Network Monitor."),
    "mail.subject": ("Haftalık ağ raporu — skor {score}", "Weekly network report — score {score}"),
    # ------------------------------------------------------------ skor notları
    "grade.A": ("Çok iyi", "Excellent"),
    "grade.B": ("İyi", "Good"),
    "grade.C": ("Orta", "Fair"),
    "grade.D": ("Zayıf", "Weak"),
    "grade.F": ("Kritik", "Critical"),
    # ------------------------------------------------------------ tarama aşamaları
    "phase.discovery": ("Keşif", "Discovery"),
    "phase.discovery_net": ("Keşif: {label} ({cidr})", "Discovery: {label} ({cidr})"),
    "phase.names": ("İsim çözümleme (DNS, mDNS)", "Name resolution (DNS, mDNS)"),
    "phase.matching": ("Gizli MAC eşleştirme", "Private MAC matching"),
    "phase.ssdp": ("SSDP / UPnP keşfi", "SSDP / UPnP discovery"),
    "phase.ports": ("Port, servis ve işletim sistemi taraması", "Port, service and OS scan"),
    "phase.security": ("Güvenlik analizi", "Security analysis"),
    "phase.router": ("Router / UPnP denetimi", "Router / UPnP audit"),
    "phase.diff": ("Fark ve skor hesaplama", "Computing diff and score"),
    "phase.done": ("Bitti", "Done"),
    # ------------------------------------------------------------ bildirim
    "notify.batch_title": ("Ağ izleyici: {n} yeni olay", "Network monitor: {n} new events"),
    "notify.more": ("… ve {n} olay daha", "… and {n} more events"),
    "notify.test_title": ("Test bildirimi", "Test notification"),
    "notify.test_body": ("Ağ izleyici bildirimleri çalışıyor ✅", "Network monitor notifications are working ✅"),
    # ------------------------------------------------------------ API hataları
    "err.device_not_found": ("Cihaz bulunamadı", "Device not found"),
    "err.alias_not_found": ("MAC kaydı bulunamadı", "MAC record not found"),
    "err.merge_self": ("Bir cihaz kendisiyle birleştirilemez", "A device cannot be merged with itself"),
    "err.split_last": ("Cihazın tek MAC adresi ayrılamaz", "A device's only MAC address cannot be split off"),
    "err.bad_type": ("Geçersiz cihaz tipi", "Invalid device type"),
    "err.bad_kind": ("kind 'quick' veya 'deep' olmalı", "kind must be 'quick' or 'deep'"),
    "err.scan_running": ("Bir tarama zaten çalışıyor", "A scan is already running"),
    "err.scan_not_found": ("Tarama bulunamadı", "Scan not found"),
    "err.finding_not_found": ("Bulgu bulunamadı", "Finding not found"),
    "err.no_urls": ("Bildirim adresi girilmemiş", "No notification URL given"),
    "err.notify_failed": ("Bildirim gönderilemedi; adresleri ve log'ları kontrol edin", "Notification failed; check the URLs and logs"),
    "err.bad_cidr": ("Geçersiz CIDR (ör. 192.168.1.0/24)", "Invalid CIDR (e.g. 192.168.1.0/24)"),
    "err.cidr_too_big": ("En fazla /16 büyüklüğünde ağ taranabilir", "Networks larger than /16 cannot be scanned"),
    "err.bad_mode": ("mode: auto, arp veya ping", "mode must be auto, arp or ping"),
    "err.subnet_exists": ("Bu ağ zaten ekli", "This network already exists"),
    "err.subnet_not_found": ("Ağ bulunamadı", "Network not found"),
    "err.bad_mac": ("Geçersiz MAC adresi", "Invalid MAC address"),
    "err.bad_ip": ("Geçersiz IP adresi", "Invalid IP address"),
    "err.report_no_target": ("Önce Ayarlar'dan bir bildirim adresi ekleyin", "Add a notification URL in Settings first"),
    "err.report_failed": ("Rapor gönderilemedi", "Report could not be sent"),
    "err.login_required": ("Giriş gerekli", "Login required"),
    "err.suggestion_not_found": ("Eşleşme önerisi bulunamadı", "Match suggestion not found"),
    "err.bad_setting": ("Geçersiz ayar değeri: {key}", "Invalid setting value: {key}"),
    # ------------------------------------------------------------ JavaScript
    "js.scanning": ("Taranıyor", "Scanning"),
    "js.scan_done": ("Tarama tamamlandı", "Scan finished"),
    "js.scan_error": ("Tarama hatası: {error}", "Scan error: {error}"),
    "js.deep_started": ("Derin tarama başlatıldı (birkaç dakika sürebilir)", "Deep scan started (may take a few minutes)"),
    "js.quick_started": ("Hızlı keşif başlatıldı", "Quick scan started"),
    "js.saved": ("Kaydedildi", "Saved"),
    "js.settings_saved": ("Ayarlar kaydedildi", "Settings saved"),
    "js.subnet_saved": ("Ağ kaydedildi", "Network saved"),
    "js.confirm_delete_device": ("Bu cihaz ve tüm geçmişi silinsin mi? Ağda tekrar görülürse yeni cihaz olarak eklenir.",
                                 "Delete this device and its entire history? It will be added as a new device if seen again."),
    "js.pick_device": ("Önce bir cihaz seçin", "Select a device first"),
    "js.confirm_merge": ("Bu kayıt seçilen cihaza taşınacak ve silinecek. Devam edilsin mi?", "This record will be moved into the selected device and deleted. Continue?"),
    "js.confirm_delete_subnet": ("Bu ağ listeden kaldırılsın mı? Cihaz kayıtları silinmez.", "Remove this network? Device records are kept."),
    "js.test_sent": ("Test bildirimi gönderildi", "Test notification sent"),
    "js.gw_confirmed": ("Ağ geçidi MAC'i onaylandı", "Gateway MAC confirmed"),
    "js.dhcp_confirmed": ("DHCP sunucusu onaylandı", "DHCP server confirmed"),
    "js.probing": ("DHCP yoklaması yapılıyor (~6 sn)…", "Probing DHCP (~6 s)…"),
    "js.probe_error": ("Hata: {error}", "Error: {error}"),
    "js.probe_result": ("{n} DHCP teklifi alındı", "{n} DHCP offers received"),
    "js.report_sent": ("Rapor gönderildi", "Report sent"),
    "js.map_empty": ("Henüz cihaz yok.", "No devices yet."),
    "js.map_error": ("Harita yüklenemedi: {error}", "Map could not be loaded: {error}"),
    "js.map_label": ("Ağ haritası", "Network map"),
    "js.map_gateway": ("Ağ geçidi", "Gateway"),
    "js.map_other": ("Diğer", "Other"),
    "js.open_ports": ("{n} açık port", "{n} open ports"),
    "js.merged": ("Kayıtlar birleştirildi", "Records merged"),
    "js.rejected": ("Öneri kaldırıldı; bu çift bir daha önerilmeyecek", "Suggestion dismissed; this pair won't be suggested again"),
    # ------------------------------------------------------------ bulgular (f.<id>.title / desc / fix)
    "f.telnet.title": ("Telnet açık", "Telnet is open"),
    "f.telnet.desc": ("Telnet trafiği (şifreler dahil) şifrelenmeden iletilir.", "Telnet traffic (including passwords) is sent unencrypted."),
    "f.telnet.fix": ("Telnet'i kapatın, gerekiyorsa SSH kullanın. IoT cihazlarda firmware güncellemesi yapın.", "Disable Telnet and use SSH if needed. Update the firmware on IoT devices."),
    "f.telnet-alt.title": ("Telnet (alternatif port) açık", "Telnet (alternate port) is open"),
    "f.telnet-alt.desc": ("Mirai gibi IoT botnetlerinin hedeflediği alternatif Telnet portu.", "Alternate Telnet port targeted by IoT botnets such as Mirai."),
    "f.telnet-alt.fix": ("Cihazın yönetim arayüzünden Telnet'i kapatın ve firmware'i güncelleyin.", "Disable Telnet in the device's admin interface and update its firmware."),
    "f.ftp.title": ("Şifrelenmemiş FTP", "Unencrypted FTP"),
    "f.ftp.desc": ("FTP kimlik bilgilerini düz metin olarak iletir.", "FTP sends credentials in plain text."),
    "f.ftp.fix": ("SFTP/FTPS kullanın veya FTP servisini kapatın.", "Use SFTP/FTPS or disable the FTP service."),
    "f.docker-api.title": ("Şifresiz Docker API açık", "Unauthenticated Docker API exposed"),
    "f.docker-api.desc": ("Docker daemon API'si kimlik doğrulamasız erişime açık; host üzerinde tam yetki sağlar.", "The Docker daemon API is reachable without authentication and grants full control of the host."),
    "f.docker-api.fix": ("Docker API'yi yalnızca unix soketinden dinleyin veya TLS (2376) ile koruyun.", "Expose the Docker API only via the unix socket or protect it with TLS (2376)."),
    "f.vnc.title": ("VNC açık", "VNC is open"),
    "f.vnc.desc": ("Uzak masaüstü erişimi; zayıf şifreler sıklıkla istismar edilir.", "Remote desktop access; weak passwords are frequently exploited."),
    "f.vnc.fix": ("VNC'yi kullanmıyorsanız kapatın, güçlü şifre ve mümkünse SSH tüneli kullanın.", "Disable VNC if unused; use a strong password and ideally an SSH tunnel."),
    "f.rdp.title": ("RDP (Uzak Masaüstü) açık", "RDP (Remote Desktop) is open"),
    "f.rdp.desc": ("Windows Uzak Masaüstü ağda erişilebilir.", "Windows Remote Desktop is reachable on the network."),
    "f.rdp.fix": ("Gerekmiyorsa kapatın; Ağ Düzeyinde Kimlik Doğrulama (NLA) açık olsun, internete asla yönlendirmeyin.", "Disable it if not needed; keep Network Level Authentication (NLA) on and never forward it to the internet."),
    "f.mqtt.title": ("Şifrelenmemiş MQTT", "Unencrypted MQTT"),
    "f.mqtt.desc": ("MQTT broker'ı TLS olmadan çalışıyor; kimlik doğrulaması kapalı olabilir.", "The MQTT broker runs without TLS; authentication may be disabled."),
    "f.mqtt.fix": ("Kimlik doğrulamayı açın ve 8883 (TLS) portunu kullanın.", "Enable authentication and use port 8883 (TLS)."),
    "f.redis.title": ("Redis ağda açık", "Redis exposed on the network"),
    "f.redis.desc": ("Redis varsayılan olarak kimlik doğrulamasızdır.", "Redis has no authentication by default."),
    "f.redis.fix": ("Redis'i yalnızca localhost'ta dinletin veya 'requirepass' ayarlayın.", "Bind Redis to localhost or set 'requirepass'."),
    "f.mongodb.title": ("MongoDB ağda açık", "MongoDB exposed on the network"),
    "f.mongodb.desc": ("Veritabanı ağdaki tüm cihazlara açık.", "The database is reachable from every device on the network."),
    "f.mongodb.fix": ("bindIp ile erişimi sınırlayın ve kimlik doğrulamayı açın.", "Restrict access with bindIp and enable authentication."),
    "f.elasticsearch.title": ("Elasticsearch ağda açık", "Elasticsearch exposed on the network"),
    "f.elasticsearch.desc": ("Elasticsearch HTTP API'si ağa açık.", "The Elasticsearch HTTP API is exposed to the network."),
    "f.elasticsearch.fix": ("Güvenlik özelliklerini (xpack.security) açın veya erişimi sınırlayın.", "Enable security features (xpack.security) or restrict access."),
    "f.memcached.title": ("Memcached ağda açık", "Memcached exposed on the network"),
    "f.memcached.desc": ("Memcached kimlik doğrulaması içermez.", "Memcached has no authentication."),
    "f.memcached.fix": ("Yalnızca localhost'ta dinletin.", "Bind it to localhost only."),
    "f.mysql.title": ("MySQL/MariaDB ağda açık", "MySQL/MariaDB exposed on the network"),
    "f.mysql.desc": ("Veritabanı portu ağdaki cihazlara açık.", "The database port is reachable from the network."),
    "f.mysql.fix": ("Gerekmiyorsa bind-address=127.0.0.1 kullanın.", "Use bind-address=127.0.0.1 if remote access is not needed."),
    "f.postgres.title": ("PostgreSQL ağda açık", "PostgreSQL exposed on the network"),
    "f.postgres.desc": ("Veritabanı portu ağdaki cihazlara açık.", "The database port is reachable from the network."),
    "f.postgres.fix": ("listen_addresses ve pg_hba.conf ile erişimi sınırlayın.", "Restrict access with listen_addresses and pg_hba.conf."),
    "f.rtsp.title": ("RTSP video yayını açık", "RTSP video stream is open"),
    "f.rtsp.desc": ("Kamera/medya yayını ağda erişilebilir; çoğu kamera zayıf varsayılan şifre kullanır.", "A camera/media stream is reachable; many cameras ship with weak default passwords."),
    "f.rtsp.fix": ("Kameranın varsayılan şifresini değiştirin, firmware'i güncelleyin.", "Change the camera's default password and update its firmware."),
    "f.tr069.title": ("TR-069 (CWMP) yönetim portu açık", "TR-069 (CWMP) management port is open"),
    "f.tr069.desc": ("ISS uzaktan yönetim protokolü; geçmişte ciddi zafiyetler barındırdı.", "ISP remote management protocol with a history of serious vulnerabilities."),
    "f.tr069.fix": ("Router firmware'ini güncel tutun; mümkünse TR-069'u kapatın.", "Keep the router firmware up to date; disable TR-069 if possible."),
    "f.ftp-anon.title": ("Anonim FTP girişi açık", "Anonymous FTP login allowed"),
    "f.ftp-anon.desc": ("Kimlik doğrulaması olmadan FTP sunucusundaki dosyalara erişilebiliyor.", "Files on the FTP server can be accessed without authentication."),
    "f.ftp-anon.fix": ("Anonim erişimi kapatın.", "Disable anonymous access."),
    "f.smbv1.title": ("SMBv1 etkin", "SMBv1 enabled"),
    "f.smbv1.desc": ("Eski SMBv1 protokolü WannaCry/EternalBlue gibi saldırılara açıktır.", "The legacy SMBv1 protocol is vulnerable to attacks such as WannaCry/EternalBlue."),
    "f.smbv1.fix": ("SMBv1'i devre dışı bırakın (Windows: 'SMB 1.0/CIFS Dosya Paylaşımı Desteği' özelliğini kaldırın).", "Disable SMBv1 (Windows: remove the 'SMB 1.0/CIFS File Sharing Support' feature)."),
    "f.default-creds.title": ("Varsayılan şifre ile giriş yapılabiliyor", "Login possible with default credentials"),
    "f.default-creds.desc": ("Web arayüzü bilinen varsayılan kullanıcı adı/şifre ile erişime açık:\n{accounts}", "The web interface accepts a well-known default username/password:\n{accounts}"),
    "f.default-creds.fix": ("Varsayılan şifreyi hemen değiştirin.", "Change the default password immediately."),
    "f.tls-expired.title": ("TLS sertifikasının süresi dolmuş", "TLS certificate expired"),
    "f.tls-expired.desc": ("Port {port} sertifikası {date} tarihinde sona ermiş.", "The certificate on port {port} expired on {date}."),
    "f.tls-expired.fix": ("Sertifikayı yenileyin (ör. cihaz firmware'i veya Let's Encrypt).", "Renew the certificate (e.g. device firmware or Let's Encrypt)."),
    "f.tls-expiring.title": ("TLS sertifikası yakında sona eriyor", "TLS certificate expires soon"),
    "f.tls-expiring.desc": ("Port {port} sertifikası {date} tarihinde sona erecek.", "The certificate on port {port} expires on {date}."),
    "f.tls-expiring.fix": ("Sertifikayı süresi dolmadan yenileyin.", "Renew the certificate before it expires."),
    "f.tls-selfsigned.title": ("Kendinden imzalı TLS sertifikası", "Self-signed TLS certificate"),
    "f.tls-selfsigned.desc": ("Port {port} kendinden imzalı sertifika kullanıyor; tarayıcı uyarıları ortadaki adam saldırılarını ayırt etmeyi zorlaştırır.",
                              "Port {port} uses a self-signed certificate; browser warnings make man-in-the-middle attacks harder to spot."),
    "f.tls-selfsigned.fix": ("Mümkünse güvenilir bir CA'dan sertifika kullanın.", "Use a certificate from a trusted CA if possible."),
    "f.vulners.title": ("Bilinen zafiyetler: {product}", "Known vulnerabilities: {product}"),
    "f.vulners.desc": ("{count} bilinen zafiyet (en yüksek CVSS {top}). Açık exploit sayısı: {exploits}.", "{count} known vulnerabilities (highest CVSS {top}). Public exploits: {exploits}."),
    "f.vulners.fix": ("Yazılımı/firmware'i en güncel sürüme yükseltin.", "Upgrade the software/firmware to the latest version."),
    "f.router-http.title": ("Router yönetim paneli şifrelenmemiş HTTP üzerinden", "Router admin panel served over unencrypted HTTP"),
    "f.router-http.desc": ("Yönetim şifresi ağda düz metin olarak iletilir.", "The admin password travels over the network in plain text."),
    "f.router-http.fix": ("Router ayarlarından HTTPS yönetimini etkinleştirin.", "Enable HTTPS management in the router settings."),
    "f.upnp-enabled.title": ("Router'da UPnP açık", "UPnP enabled on the router"),
    "f.upnp-enabled.desc": ("UPnP IGD, ağdaki herhangi bir cihazın (kötü amaçlı yazılım dahil) router'da kimlik doğrulaması olmadan internete port açmasına izin verir.{model}",
                            "UPnP IGD lets any device on the network (including malware) open ports to the internet on the router without authentication.{model}"),
    "f.upnp-enabled.fix": ("Gerekmiyorsa router ayarlarından UPnP'yi kapatın; gerekiyorsa açılan yönlendirmeleri düzenli kontrol edin.",
                           "Disable UPnP in the router settings if not needed; otherwise review the opened forwards regularly."),
    "f.wan-forward.title": ("İnternete açık port: {proto} {ext} → {client}:{iport}", "Port exposed to the internet: {proto} {ext} → {client}:{iport}"),
    "f.wan-forward.desc": ("UPnP ile oluşturulmuş yönlendirme ({desc}). Bu servis internetten erişilebilir{via}.", "Forward created via UPnP ({desc}). This service is reachable from the internet{via}."),
    "f.wan-forward.fix": ("Bu yönlendirmeyi tanımıyorsanız kaldırın ve ilgili cihazı inceleyin.", "If you don't recognise this forward, remove it and inspect the device."),
    "f.arp_spoof.title": ("Olası ARP spoofing saldırısı", "Possible ARP spoofing attack"),
    "f.arp_spoof.desc": ("Ağ geçidi ({ip}) için farklı bir MAC adresi yayınlandı: {mac} (beklenen {expected}). Olası ARP spoofing / ortadaki adam saldırısı.",
                         "A different MAC address was announced for the gateway ({ip}): {mac} (expected {expected}). Possible ARP spoofing / man-in-the-middle attack."),
    "f.arp_spoof.fix": ("Ağdaki tanımadığınız cihazları kontrol edin; saldırgan MAC adresini router'da engelleyin. Router'ı değiştirdiyseniz Ayarlar sayfasından yeni ağ geçidi MAC'ini onaylayın.",
                        "Check for unknown devices on the network and block the attacker's MAC on the router. If you replaced the router, confirm the new gateway MAC in Settings."),
    "f.rogue_dhcp.title": ("Sahte (rogue) DHCP sunucusu", "Rogue DHCP server"),
    "f.rogue_dhcp.desc": ("{detail}", "{detail}"),
    "f.rogue_dhcp.fix": ("Ağa bağlı ikinci bir router/erişim noktası DHCP dağıtıyor olabilir; o cihazda DHCP'yi kapatın.",
                         "A second router/access point may be handing out DHCP leases; disable DHCP on that device."),
    "f.upnp-model": (" Model: {model}.", " Model: {model}."),
    "f.via_ip": (" ({ip} üzerinden)", " (via {ip})"),
    "f.no_desc": ("açıklama yok", "no description"),
}


class _Safe(dict):
    def __missing__(self, key):  # eksik parametre şablonu bozmasın
        return ""


def get_lang() -> str:
    return _lang.get()


def set_lang(lang: str):
    return _lang.set(lang if lang in LANGS else DEFAULT_LANG)


@contextmanager
def use_lang(lang: str) -> Iterator[None]:
    token = set_lang(lang)
    try:
        yield
    finally:
        _lang.reset(token)


def has(key: str) -> bool:
    return key in M


def tl(lang: str, key: str, /, **params: Any) -> str:
    pair = M.get(key)
    if pair is None:
        return key
    text = pair[1] if lang == "en" else pair[0]
    if not params:
        return text
    try:
        return text.format_map(_Safe({k: ("" if v is None else v) for k, v in params.items()}))
    except (ValueError, IndexError):
        return text


def t(key: str, /, **params: Any) -> str:
    return tl(get_lang(), key, **params)


def pick_lang(cookie: str | None, accept_language: str | None, default: str) -> str:
    if cookie in LANGS:
        return cookie
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LANGS:
            return code
    return default if default in LANGS else DEFAULT_LANG


def js_catalog(lang: str) -> str:
    """Etkin dilin ``js.*`` metinleri (base.html'e gömülür)."""
    data = {k[3:]: (v[1] if lang == "en" else v[0]) for k, v in M.items() if k.startswith("js.")}
    return json.dumps(data, ensure_ascii=False)


def default_language() -> str:
    from app import settings_store

    try:
        lang = settings_store.get("default_language")
    except Exception:
        return DEFAULT_LANG
    return lang if lang in LANGS else DEFAULT_LANG


# ------------------------------------------------------------------ veritabanı kayıtlarını çeviri
def _loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except ValueError:
        return {}


def finding_text(msg_id: str | None, params: dict | str | None, field: str, fallback: str = "") -> str:
    """Bulgu başlığı/açıklaması/önerisi: katalogda varsa etkin dilde üretilir, yoksa kayıtlı metin."""
    if isinstance(params, str):
        params = _loads(params)
    key = f"f.{msg_id}.{field}"
    if msg_id and key in M:
        return t(key, **_prep_finding_params(msg_id, params or {}))
    return fallback


def _prep_finding_params(msg_id: str, params: dict) -> dict:
    """Bazı bulgularda parametreler önce etkin dilde bir cümle parçasına dönüştürülür."""
    p = dict(params)
    if msg_id == "upnp-enabled":
        p["model"] = t("f.upnp-model", model=p["model"]) if p.get("model") else ""
    elif msg_id == "wan-forward":
        p["desc"] = p.get("desc") or t("f.no_desc")
        p["via"] = t("f.via_ip", ip=p["ext_ip"]) if p.get("ext_ip") else ""
    elif msg_id == "rogue_dhcp" and p.get("msg"):
        p["detail"] = t(f"ev.{p['msg']}", **p)
    return p


def event_text(kind: str, params: dict | str | None, fallback: str = "") -> str:
    """Olay mesajı: yapısal parametrelerden etkin dilde üretilir; eski kayıtlarda kayıtlı metin."""
    if isinstance(params, str):
        params = _loads(params)
    if not params:
        return fallback
    p = dict(params)
    if kind == "finding":
        title = finding_text(p.get("msg_id"), p.get("fparams") or {}, "title", p.get("title", fallback))
        return t("finding.reopened", title=title) if p.get("reopened") else title
    if kind in ("arp_spoof", "rogue_dhcp", "ip_mac_changed") and p.get("msg"):
        return t(f"ev.{p['msg']}", **p)
    if kind == "joined":
        if not p.get("vendor"):
            p["vendor"] = t("ev.random_mac") if p.get("random") else t("ev.unknown_vendor")
        if not p.get("mac"):
            p["mac"] = t("ev.no_mac")
    if kind == "merged":
        key = "ev.merged_auto_score" if p.get("auto") and p.get("score") else ("ev.merged_auto" if p.get("auto") else "ev.merged")
        return t(key, **p)
    key = f"ev.{kind}"
    return t(key, **p) if key in M else fallback


def diff_text(change: dict) -> str:
    kind = change.get("kind", "")
    p = change.get("params")
    if not p:
        return change.get("detail", "")
    if kind in ("finding_new", "finding_resolved"):
        return finding_text(p.get("msg_id"), p.get("fparams") or {}, "title", p.get("title", change.get("detail", "")))
    key = f"diffd.{kind}"
    return t(key, **p) if key in M else change.get("detail", "")


def change_name(change: dict) -> str:
    return t("common.network_wide") if change.get("device") == "net" else change.get("name", "")
