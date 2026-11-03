// Bulgu "yoksay" / "çözüldü" düğmeleri
document.addEventListener("click", async (ev) => {
  const ign = ev.target.closest("[data-ignore]");
  const res = ev.target.closest("[data-resolve]");
  try {
    if (ign) {
      await NS.api("POST", `/api/findings/${ign.dataset.ignore}/ignore`, { ignored: ign.dataset.value === "true" });
      location.reload();
    } else if (res) {
      await NS.api("POST", `/api/findings/${res.dataset.resolve}/resolve`);
      location.reload();
    }
  } catch (e) {
    NS.toast(e.message);
  }
});
