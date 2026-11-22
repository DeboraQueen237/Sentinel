document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain") || "domaine inconnu";
  const reason = params.get("reason") || "Domaine bloqué par la politique de prévention SENTINEL.";

  const domainEl = document.getElementById("blocked-domain");
  const reasonEl = document.getElementById("blocked-reason");
  if (domainEl) domainEl.textContent = domain;
  if (reasonEl) reasonEl.textContent = reason;

  const backBtn = document.getElementById("btn-back");
  if (backBtn) {
    backBtn.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });
  }
});
