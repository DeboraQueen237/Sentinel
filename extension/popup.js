function formatMode(mode) {
  switch (mode) {
    case "Active": return "Actif";
    case "Simulation": return "Simulation";
    case "Learning": return "Apprentissage";
    default: return mode || "—";
  }
}

function render(state) {
  const badge = document.getElementById("badge");
  const statusText = document.getElementById("status-text");
  const modeVal = document.getElementById("mode-value");
  const blockedCount = document.getElementById("blocked-count");
  const eventsCount = document.getElementById("events-count");
  const errorText = document.getElementById("error-text");

  if (!state) return;

  if (state.connected) {
    badge.className = "shield-badge shield-ok";
    statusText.textContent = "Connecté à Sentinel.Agent";
    statusText.className = "status-pill status-ok";
  } else {
    badge.className = "shield-badge shield-idle";
    statusText.textContent = "Agent local déconnecté";
    statusText.className = "status-pill status-off";
  }

  modeVal.textContent = formatMode(state.mode);
  blockedCount.textContent = String((state.blockedDomains || []).length);
  eventsCount.textContent = String(state.eventsSent || 0);
  errorText.textContent = state.connected ? "" : (state.lastError || "");
}

function refresh() {
  chrome.runtime.sendMessage({ action: "getStatus" }, (resp) => {
    if (chrome.runtime.lastError) {
      chrome.storage.local.get("sentinelState", (res) => render(res.sentinelState));
      return;
    }
    render(resp);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  refresh();
  const btn = document.getElementById("btn-reconnect");
  if (btn) {
    btn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "reconnect" }, () => {
        setTimeout(refresh, 600);
      });
    });
  }
});
