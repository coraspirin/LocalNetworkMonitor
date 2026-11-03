// Ortak yardımcılar: API çağrıları, bildirim balonu ve tarama ilerleme göstergesi.
(function () {
  "use strict";

  async function api(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* boş yanıt */ }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || res.statusText;
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    return data;
  }

  // Çeviri: window.NS_I18N (base.html) içindeki "js.*" anahtarları
  function t(key, params) {
    let text = (window.NS_I18N && window.NS_I18N[key]) || key;
    if (params) Object.keys(params).forEach((k) => { text = text.split("{" + k + "}").join(String(params[k])); });
    return text;
  }

  let toastTimer;
  function toast(msg) {
    const el = document.getElementById("toast");
    if (!el) return alert(msg);
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
  }

  // Tarama durumu
  let pollTimer = null;
  let wasRunning = false;
  async function pollStatus() {
    try {
      const st = await api("GET", "/api/scans/status");
      const box = document.getElementById("scan-progress");
      document.querySelectorAll("[data-scan]").forEach((b) => (b.disabled = st.running));
      if (box) {
        box.classList.toggle("show", !!st.running);
        const phase = box.querySelector(".phase");
        const fill = box.querySelector(".bar > span");
        if (phase) phase.textContent = st.running ? (st.phase || t("scanning")) + (st.total ? ` (${st.done || 0}/${st.total})` : "") : "";
        if (fill) fill.style.width = st.total ? Math.round(((st.done || 0) * 100) / st.total) + "%" : "15%";
      }
      if (wasRunning && !st.running) {
        toast(st.error ? t("scan_error", { error: st.error }) : t("scan_done"));
        if (document.body.dataset.reloadOnScan === "1") setTimeout(() => location.reload(), 800);
      }
      wasRunning = st.running;
      clearTimeout(pollTimer);
      pollTimer = setTimeout(pollStatus, st.running ? 2000 : 15000);
    } catch (e) {
      clearTimeout(pollTimer);
      pollTimer = setTimeout(pollStatus, 15000);
    }
  }

  async function startScan(kind) {
    try {
      await api("POST", "/api/scans", { kind });
      toast(kind === "deep" ? t("deep_started") : t("quick_started"));
      wasRunning = true;
      setTimeout(pollStatus, 500);
    } catch (e) {
      toast(e.message);
    }
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-scan]");
    if (btn) {
      ev.preventDefault();
      startScan(btn.dataset.scan);
    }
  });

  document.addEventListener("DOMContentLoaded", pollStatus);

  window.NS = { api, toast, startScan, t };
})();
