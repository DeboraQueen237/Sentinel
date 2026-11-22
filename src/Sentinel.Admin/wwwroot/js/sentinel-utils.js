/* SENTINEL Admin — Utilitaires locaux (thème, téléchargement binaire, presse-papiers) */
window.sentinelUtils = (() => {
    const THEME_KEY = "sentinel-theme";

    function getTheme() {
        try {
            const saved = localStorage.getItem(THEME_KEY);
            if (saved === "light" || saved === "dark") return saved;
        } catch {
            // Ignoré
        }
        return document.documentElement.getAttribute("data-theme") || "dark";
    }

    function setTheme(theme) {
        const normalized = theme === "light" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", normalized);
        try {
            localStorage.setItem(THEME_KEY, normalized);
        } catch {
            // Ignoré
        }
        if (window.sentinelGraph && typeof window.sentinelGraph.updateTheme === "function") {
            window.sentinelGraph.updateTheme();
        }
        return normalized;
    }

    function toggleTheme() {
        const current = getTheme();
        return setTheme(current === "dark" ? "light" : "dark");
    }

    function downloadBase64File(fileName, contentType, base64Data) {
        const binary = atob(base64Data);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: contentType || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = fileName || "sentinel-export";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 1500);
    }

    function downloadDataUrl(fileName, dataUrl) {
        const link = document.createElement("a");
        link.href = dataUrl;
        link.download = fileName || "sentinel-graphe.png";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    async function copyText(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch {
            // Fallback ci-dessous
        }
        try {
            const ta = document.createElement("textarea");
            ta.value = text;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            const ok = document.execCommand("copy");
            document.body.removeChild(ta);
            return ok;
        } catch {
            return false;
        }
    }

    return {
        getTheme,
        setTheme,
        toggleTheme,
        downloadBase64File,
        downloadDataUrl,
        copyText
    };
})();
