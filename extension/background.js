// SENTINEL — Service Worker Manifest V3 (Chrome / Edge)
// Respect de la vie privée (§2.1, §6.8) :
//   - Aucun accès au DOM, au contenu des pages, aux formulaires ou aux mots de passe.
//   - Les paramètres de requête (?…), fragments (#…) et identifiants sont retirés avant transmission.

const NATIVE_HOST_NAME = "com.sentinel.browserhost";
const DYNAMIC_RULE_ID_OFFSET = 10000;

let nativePort = null;
let reconnectTimer = null;
let reconnectDelayMs = 2000;

const state = {
  connected: false,
  browserEnabled: true,
  mode: "Learning",
  blockedDomains: [],
  eventsSent: 0,
  lastError: null
};

// Suivi par onglet des redirections et de la dernière URL visitée (mémoire uniquement)
const tabHistory = new Map();

function detectBrowserName() {
  const ua = navigator.userAgent || "";
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("Chrome/")) return "Chrome";
  return "Chromium";
}

function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    const domain = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const port = parsed.port ? `:${parsed.port}` : "";
    const path = (parsed.pathname || "/").slice(0, 200);
    return {
      url: `${parsed.protocol}//${domain}${port}${path}`,
      domain
    };
  } catch {
    return null;
  }
}

async function persistState() {
  try {
    await chrome.storage.local.set({ sentinelState: { ...state } });
  } catch {
    // Ignoré si storage indisponible.
  }
}

function connectNative() {
  if (nativePort) return;
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    state.lastError = null;

    nativePort.onMessage.addListener((message) => {
      handleNativeMessage(message).catch(() => {});
    });

    nativePort.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : "Déconnecté";
      nativePort = null;
      state.connected = false;
      state.lastError = err;
      persistState();
      scheduleReconnect();
    });

    nativePort.postMessage({ type: "getStatus" });
  } catch (err) {
    nativePort = null;
    state.connected = false;
    state.lastError = err && err.message ? err.message : String(err);
    persistState();
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    reconnectDelayMs = Math.min(reconnectDelayMs * 2, 15000);
    connectNative();
  }, reconnectDelayMs);
}

async function handleNativeMessage(msg) {
  if (!msg || typeof msg !== "object") return;

  switch (msg.type) {
    case "status":
    case "settings":
      state.connected = Boolean(msg.connected);
      if (typeof msg.browserEnabled === "boolean") {
        state.browserEnabled = msg.browserEnabled;
      }
      if (msg.mode) {
        state.mode = msg.mode;
      }
      if (Array.isArray(msg.blockedDomains)) {
        state.blockedDomains = msg.blockedDomains;
        await applyBlockedDomains(msg.blockedDomains, "Domaine bloqué par SENTINEL");
      }
      if (state.connected) {
        reconnectDelayMs = 2000;
        state.lastError = null;
      }
      await persistState();
      break;

    case "blockDomains":
      if (Array.isArray(msg.domains)) {
        state.blockedDomains = msg.domains;
        await applyBlockedDomains(msg.domains, msg.reason || "Domaine bloqué par SENTINEL");
        await persistState();
      }
      break;

    case "closeTab":
      await handleCloseTabCommand(msg);
      break;
  }
}

async function applyBlockedDomains(domains, reason) {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((r) => r.id);

    const uniqueDomains = Array.from(
      new Set(
        (domains || [])
          .map((d) => String(d || "").trim().toLowerCase().replace(/\.$/, ""))
          .filter((d) => d.length >= 3 && d !== "localhost")
      )
    ).slice(0, 500);

    const safeReason = encodeURIComponent(String(reason || "Menace détectée par SENTINEL").slice(0, 180));
    const addRules = uniqueDomains.map((domain, index) => ({
      id: DYNAMIC_RULE_ID_OFFSET + index,
      priority: 1,
      action: {
        type: "redirect",
        redirect: {
          extensionPath: `/blocked.html?domain=${encodeURIComponent(domain)}&reason=${safeReason}`
        }
      },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ["main_frame"]
      }
    }));

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
  } catch {
    // Échec silencieux si les règles dynamiques ne peuvent pas être mises à jour.
  }
}

async function handleCloseTabCommand(cmd) {
  try {
    const parsedId = cmd.tabId !== undefined && cmd.tabId !== null ? Number(cmd.tabId) : NaN;
    if (Number.isInteger(parsedId) && parsedId > 0) {
      await chrome.tabs.remove(parsedId);
      return;
    }

    if (cmd.url) {
      const target = sanitizeUrl(cmd.url);
      if (target) {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          const tabSanitized = sanitizeUrl(tab.url);
          if (tabSanitized && tabSanitized.domain === target.domain && tab.id) {
            await chrome.tabs.remove(tab.id);
          }
        }
      }
    }
  } catch {
    // L'onglet est peut-être déjà fermé.
  }
}

function sendEvent(eventPayload) {
  if (!state.browserEnabled) return;
  if (!nativePort) {
    connectNative();
    return;
  }

  try {
    nativePort.postMessage({
      type: "event",
      browser: detectBrowserName(),
      ...eventPayload
    });
    state.eventsSent += 1;
    persistState();
  } catch {
    // Reconnexion gérée par onDisconnect.
  }
}

// ---------------------------------------------------------------------------
// Écouteurs de navigation (métadonnées uniquement, cadre principal frameId=0)
// ---------------------------------------------------------------------------

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const clean = sanitizeUrl(details.url);
  if (!clean) return;

  const prev = tabHistory.get(details.tabId) || { lastUrl: null, redirects: 0 };
  tabHistory.set(details.tabId, {
    lastUrl: prev.lastUrl,
    pendingReferrer: prev.lastUrl,
    redirects: 0
  });
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const clean = sanitizeUrl(details.url);
  if (!clean) return;

  const qualifiers = details.transitionQualifiers || [];
  const isRedirect = qualifiers.includes("client_redirect") || qualifiers.includes("server_redirect");
  const isLinkClick = details.transitionType === "link";

  const entry = tabHistory.get(details.tabId) || { lastUrl: null, pendingReferrer: null, redirects: 0 };
  const redirectCount = isRedirect ? entry.redirects + 1 : 0;
  const referrer = entry.pendingReferrer || entry.lastUrl;

  tabHistory.set(details.tabId, {
    lastUrl: clean.url,
    pendingReferrer: null,
    redirects: redirectCount
  });

  const eventType = isRedirect ? "Redirect" : (isLinkClick ? "LinkClicked" : "UrlVisited");
  sendEvent({
    eventType,
    url: clean.url,
    domain: clean.domain,
    referrer,
    redirectCount,
    tabId: details.tabId
  });
});

chrome.downloads.onCreated.addListener((item) => {
  const clean = sanitizeUrl(item.finalUrl || item.url);
  if (!clean) return;

  const cleanRef = sanitizeUrl(item.referrer);
  const rawName = item.filename ? item.filename.split(/[\\/]/).pop() : "";

  sendEvent({
    eventType: "DownloadStarted",
    url: clean.url,
    domain: clean.domain,
    referrer: cleanRef ? cleanRef.url : null,
    fileName: rawName
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabHistory.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request && request.action === "getStatus") {
    sendResponse({ ...state });
    return true;
  }
  if (request && request.action === "reconnect") {
    if (nativePort) {
      try { nativePort.disconnect(); } catch {}
      nativePort = null;
    }
    reconnectDelayMs = 2000;
    connectNative();
    sendResponse({ ok: true });
    return true;
  }
  return false;
});

connectNative();
