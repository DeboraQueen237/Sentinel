/* SENTINEL Admin v2.2 — Graphe causal en Arbre (Racines → Branches → Nœuds → Alertes) & Flux directs/indirects */
window.sentinelGraph = (() => {
    let cy = null;
    let dotNetRef = null;
    let currentLayout = "tree-lr";

    const ROLE_META = {
        Host:    { badge: "POSTE",     color: "#6366f1", rank: 0, shape: "round-rectangle" },
        User:    { badge: "COMPTE",    color: "#10b981", rank: 1, shape: "round-rectangle" },
        Device:  { badge: "USB / HID", color: "#f97316", rank: 1, shape: "round-rectangle" },
        Process: { badge: "PROCESSUS", color: "#8b5cf6", rank: 2, shape: "round-rectangle" },
        Event:   { badge: "ÉVÉNEMENT", color: "#0ea5e9", rank: 3, shape: "round-rectangle" },
        File:    { badge: "FICHIER",   color: "#eab308", rank: 4, shape: "round-rectangle" },
        Domain:  { badge: "DOMAINE",   color: "#06b6d4", rank: 4, shape: "round-rectangle" },
        Ip:      { badge: "RÉSEAU IP", color: "#38bdf8", rank: 4, shape: "round-rectangle" },
        Threat:  { badge: "MENACE",    color: "#ef4444", rank: 5, shape: "round-octagon" }
    };

    const DIRECT_EDGE_TYPES = new Set([
        "Spawned", "Wrote", "ConnectedTo", "OpenedUrl", "CopiedFromClipboard", "InvolvedIn"
    ]);

    function isLight() {
        return document.documentElement.getAttribute("data-theme") === "light";
    }

    function buildStylesheet() {
        const light = isLight();
        const cardBg = light ? "#ffffff" : "#0f172a";
        const textPrimary = light ? "#0f172a" : "#f1f5f9";
        const edgeDirect = light ? "#0284c7" : "#38bdf8";
        const edgeAlert = "#f97316";
        const edgeIndirect = light ? "#7c3aed" : "#a78bfa";
        const edgeLabelBg = light ? "rgba(248, 250, 252, 0.92)" : "rgba(15, 23, 42, 0.9)";
        const edgeLabelText = light ? "#334155" : "#cbd5e1";

        return [
            {
                selector: "node[kind = 'entity']",
                style: {
                    "shape": "data(shape)",
                    "width": "data(width)",
                    "height": "data(height)",
                    "background-color": "data(fillBg)",
                    "border-color": "data(accent)",
                    "border-width": "data(borderWidth)",
                    "label": "data(cardText)",
                    "color": textPrimary,
                    "font-size": 10.5,
                    "font-weight": 600,
                    "font-family": "Segoe UI, system-ui, sans-serif",
                    "text-valign": "center",
                    "text-halign": "center",
                    "text-wrap": "wrap",
                    "text-max-width": "148px",
                    "line-height": 1.28,
                    "underlay-color": "data(accent)",
                    "underlay-padding": "data(haloPad)",
                    "underlay-opacity": "data(haloOpacity)",
                    "underlay-shape": "round-rectangle",
                    "transition-property": "opacity, border-width",
                    "transition-duration": "180ms"
                }
            },
            {
                selector: "node[nodeType = 'Threat']",
                style: {
                    "background-color": light ? "#fef2f2" : "#2a1219",
                    "font-weight": 700,
                    "font-size": 11
                }
            },
            {
                selector: "node[nodeType = 'Host']",
                style: {
                    "background-color": light ? "#eef2ff" : "#161e3d",
                    "font-weight": 700
                }
            },
            {
                selector: "node[kind = 'entity']:selected",
                style: {
                    "border-width": 4,
                    "border-color": "#22d3ee",
                    "underlay-color": "#22d3ee",
                    "underlay-padding": 9,
                    "underlay-opacity": 0.3,
                    "z-index": 99
                }
            },
            {
                selector: "edge[flowClass = 'direct']",
                style: {
                    "width": 2.1,
                    "line-color": edgeDirect,
                    "target-arrow-color": edgeDirect,
                    "target-arrow-shape": "triangle",
                    "curve-style": "taxi",
                    "taxi-direction": "horizontal",
                    "taxi-turn": "45%",
                    "arrow-scale": 0.9,
                    "label": "data(label)",
                    "font-size": 9,
                    "font-family": "Segoe UI, sans-serif",
                    "color": edgeLabelText,
                    "text-background-color": edgeLabelBg,
                    "text-background-opacity": 0.9,
                    "text-background-padding": "2px",
                    "text-background-shape": "roundrectangle"
                }
            },
            {
                selector: "edge[flowClass = 'alert']",
                style: {
                    "width": 2.3,
                    "line-color": edgeAlert,
                    "target-arrow-color": edgeAlert,
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier",
                    "arrow-scale": 0.95,
                    "label": "data(label)",
                    "font-size": 9,
                    "color": edgeAlert,
                    "text-background-color": edgeLabelBg,
                    "text-background-opacity": 0.9,
                    "text-background-padding": "2px"
                }
            },
            {
                selector: "edge[flowClass = 'indirect']",
                style: {
                    "width": 1.9,
                    "line-style": "dashed",
                    "line-dash-pattern": [6, 4],
                    "line-color": edgeIndirect,
                    "target-arrow-color": edgeIndirect,
                    "target-arrow-shape": "vee",
                    "curve-style": "unbundled-bezier",
                    "control-point-distances": [34],
                    "control-point-weights": [0.5],
                    "arrow-scale": 0.9,
                    "label": "data(label)",
                    "font-size": 8.5,
                    "color": edgeIndirect,
                    "text-background-color": edgeLabelBg,
                    "text-background-opacity": 0.9,
                    "text-background-padding": "2px"
                }
            },
            {
                selector: "edge:selected",
                style: {
                    "width": 3.5,
                    "line-color": "#fbbf24",
                    "target-arrow-color": "#fbbf24",
                    "z-index": 90
                }
            },
            {
                selector: ".dimmed",
                style: { "opacity": 0.14 }
            },
            {
                selector: ".hidden-filter",
                style: { "display": "none" }
            },
            {
                selector: ".highlighted",
                style: { "opacity": 1, "z-index": 60 }
            }
        ];
    }

    function computeTreePositions(nodes, edges, vertical) {
        // Regroupe les nœuds par rang causal (0: Poste -> 1: Acteur -> 2: Processus -> 3: Événement -> 4: Cible -> 5: Menace)
        const ranks = new Map();
        const nodeMap = new Map();
        for (const n of nodes) {
            nodeMap.set(n.id, n);
            const r = typeof n.rank === "number" ? n.rank : 3;
            if (!ranks.has(r)) ranks.set(r, []);
            ranks.get(r).push(n);
        }

        // Index parent -> enfants pour aligner visuellement les branches d'un même arbre
        const incoming = new Map();
        for (const e of edges) {
            if (!incoming.has(e.target)) incoming.set(e.target, []);
            incoming.get(e.target).push(e.source);
        }

        const positions = {};
        const orderIndex = new Map();
        const sortedRanks = Array.from(ranks.keys()).sort((a, b) => a - b);

        const colSpacing = vertical ? 125 : 245;
        const rowSpacing = vertical ? 195 : 82;

        sortedRanks.forEach((rankKey, colIdx) => {
            const list = ranks.get(rankKey);
            list.sort((a, b) => {
                const pa = (incoming.get(a.id) || []).map(id => orderIndex.get(id)).filter(v => v !== undefined);
                const pb = (incoming.get(b.id) || []).map(id => orderIndex.get(id)).filter(v => v !== undefined);
                const avgA = pa.length ? pa.reduce((s, x) => s + x, 0) / pa.length : 999;
                const avgB = pb.length ? pb.reduce((s, x) => s + x, 0) / pb.length : 999;
                if (Math.abs(avgA - avgB) > 0.01) return avgA - avgB;
                if ((a.clusterId || "") !== (b.clusterId || "")) return (a.clusterId || "").localeCompare(b.clusterId || "");
                return (b.score || 0) - (a.score || 0);
            });

            const mid = (list.length - 1) / 2.0;
            list.forEach((n, idx) => {
                orderIndex.set(n.id, idx);
                const offset = (idx - mid) * rowSpacing;
                const depth = colIdx * colSpacing;
                positions[n.id] = vertical
                    ? { x: offset, y: depth }
                    : { x: depth, y: offset };
            });
        });

        return positions;
    }

    function buildLayoutConfig(layoutName, rawNodes, rawEdges) {
        if (layoutName === "tree-tb") {
            const pos = computeTreePositions(rawNodes, rawEdges, true);
            return { name: "preset", positions: n => pos[n.id()] || { x: 0, y: 0 }, fit: true, padding: 42 };
        }
        if (layoutName === "concentric") {
            return {
                name: "concentric",
                padding: 44,
                animate: true,
                animationDuration: 380,
                minNodeSpacing: 36,
                concentric: n => 6 - (n.data("rank") || 3),
                levelWidth: () => 1
            };
        }
        if (layoutName === "cose") {
            return {
                name: "cose",
                padding: 46,
                animate: true,
                animationDuration: 450,
                nodeRepulsion: () => 22000,
                idealEdgeLength: () => 150,
                nodeOverlap: 32
            };
        }
        // Par défaut : Arbre causal Gauche -> Droite (Racines -> Branches -> Menaces)
        const pos = computeTreePositions(rawNodes, rawEdges, false);
        return { name: "preset", positions: n => pos[n.id()] || { x: 0, y: 0 }, fit: true, padding: 44 };
    }

    function formatCardLabel(n, meta) {
        const raw = n.label || n.id;
        const clean = raw.length > 34 ? `${raw.substring(0, 32)}…` : raw;
        const scoreTag = (n.type === "Threat" || (n.type === "Event" && n.score >= 55)) ? ` · ${n.score}` : "";
        return `${meta.badge}${scoreTag}\n${clean}`;
    }

    function pickNodeAccent(n, meta) {
        if (n.type === "Threat") {
            return n.score >= 90 ? "#ef4444" : (n.score >= 75 ? "#f97316" : "#f59e0b");
        }
        if (n.type === "Event") {
            if (n.score >= 90) return "#f97316"; // Orange vif au lieu de tout peindre en rouge sang
            if (n.score >= 70) return "#f59e0b";
            return "#0ea5e9";
        }
        return meta.color;
    }

    function render(containerId, payload, layoutName, _groupClusters, netRef) {
        if (typeof cytoscape === "undefined") return;
        const container = document.getElementById(containerId);
        if (!container) return;

        destroy();
        currentLayout = layoutName || "tree-lr";
        dotNetRef = netRef;

        const light = isLight();
        const defaultCardBg = light ? "#ffffff" : "#0f172a";
        const elements = [];
        const rawNodes = [];
        const rawEdges = [];
        const nodeIdSet = new Set();

        if (payload && Array.isArray(payload.nodes)) {
            for (const n of payload.nodes) {
                nodeIdSet.add(n.id);
                const meta = ROLE_META[n.type] || ROLE_META.Event;
                const rank = typeof n.rank === "number" ? n.rank : meta.rank;
                const accent = pickNodeAccent(n, meta);
                const isThreat = n.type === "Threat";
                const nodeObj = {
                    id: n.id,
                    kind: "entity",
                    nodeType: n.type,
                    category: n.category || "",
                    mitre: n.mitre || "",
                    label: n.label || n.id,
                    cardText: formatCardLabel(n, meta),
                    score: n.score || 0,
                    level: n.level || "Info",
                    rank,
                    clusterId: n.clusterId || null,
                    shape: meta.shape,
                    accent,
                    fillBg: defaultCardBg,
                    borderWidth: isThreat ? 3.2 : 2,
                    width: isThreat ? 174 : 160,
                    height: isThreat ? 54 : 46,
                    haloPad: isThreat ? 7 : 0,
                    haloOpacity: isThreat ? 0.22 : 0
                };
                rawNodes.push(nodeObj);
                elements.push({ group: "nodes", data: nodeObj });
            }
        }

        if (payload && Array.isArray(payload.edges)) {
            for (const e of payload.edges) {
                if (!nodeIdSet.has(e.source) || !nodeIdSet.has(e.target)) continue;
                const isToThreat = String(e.target).startsWith("threat:");
                const flowClass = isToThreat
                    ? "alert"
                    : (DIRECT_EDGE_TYPES.has(e.type) ? "direct" : "indirect");

                const edgeObj = {
                    id: e.id,
                    source: e.source,
                    target: e.target,
                    edgeType: e.type,
                    flowClass,
                    weight: e.weight || 0.5,
                    label: e.label || e.type
                };
                rawEdges.push(edgeObj);
                elements.push({ group: "edges", data: edgeObj });
            }
        }

        cy = cytoscape({
            container,
            elements,
            style: buildStylesheet(),
            layout: elements.length > 0 ? buildLayoutConfig(currentLayout, rawNodes, rawEdges) : { name: "preset" },
            minZoom: 0.22,
            maxZoom: 2.8,
            wheelSensitivity: 0.25
        });

        cy.on("tap", "node[kind = 'entity']", evt => {
            const node = evt.target;
            traceBranch(node);
            const id = node.data("id");
            if (dotNetRef) dotNetRef.invokeMethodAsync("OnNodeSelected", id);
        });

        cy.on("tap", "edge", evt => {
            clearHighlight();
            const edge = evt.target;
            cy.elements().addClass("dimmed");
            edge.union(edge.connectedNodes()).removeClass("dimmed").addClass("highlighted");
            if (dotNetRef) dotNetRef.invokeMethodAsync("OnEdgeSelected", edge.data("id"));
        });

        cy.on("tap", evt => {
            if (evt.target === cy) {
                clearHighlight();
                if (dotNetRef) dotNetRef.invokeMethodAsync("OnCanvasCleared");
            }
        });
    }

    // Met en évidence toute la branche causale (racines amont + feuilles aval) du nœud cliqué
    function traceBranch(node) {
        if (!cy || !node) return;
        clearHighlight();
        const upstream = node.predecessors();
        const downstream = node.successors();
        const branch = node.union(upstream).union(downstream);
        cy.elements().addClass("dimmed");
        branch.removeClass("dimmed").addClass("highlighted");
    }

    function applyFilter(filter) {
        if (!cy) return;
        cy.elements().removeClass("hidden-filter dimmed highlighted");
        if (!filter) return;

        const q = (filter.search || "").trim().toLowerCase();
        const nodeType = filter.nodeType || "";
        const flowMode = filter.flowMode || "all";
        const hideSystemNoise = !!filter.hideSystemNoise;

        cy.nodes().forEach(n => {
            let hide = false;
            if (hideSystemNoise && n.data("category") === "System" && n.data("nodeType") === "Event") {
                hide = true;
            }
            if (!hide && nodeType && n.data("nodeType") !== nodeType) {
                hide = true;
            }
            if (hide) {
                n.addClass("hidden-filter");
                n.connectedEdges().addClass("hidden-filter");
            }
        });

        if (flowMode === "direct") {
            cy.edges("[flowClass = 'indirect']").addClass("hidden-filter");
        } else if (flowMode === "indirect") {
            cy.edges("[flowClass = 'direct']").addClass("hidden-filter");
        }

        if (q.length > 0) {
            const matched = cy.nodes().filter(n =>
                !n.hasClass("hidden-filter") &&
                (String(n.data("label") || "").toLowerCase().includes(q) ||
                 String(n.data("nodeType") || "").toLowerCase().includes(q) ||
                 String(n.data("mitre") || "").toLowerCase().includes(q)));

            if (matched.length > 0) {
                const keep = matched.union(matched.predecessors()).union(matched.successors());
                cy.elements().not(".hidden-filter").addClass("dimmed");
                keep.removeClass("dimmed").addClass("highlighted");
            }
        }
    }

    function setLayout(layoutName) {
        if (!cy) return;
        currentLayout = layoutName || "tree-lr";
        const rawNodes = cy.nodes().not(".hidden-filter").map(n => n.data());
        const rawEdges = cy.edges().not(".hidden-filter").map(e => e.data());
        cy.layout(buildLayoutConfig(currentLayout, rawNodes, rawEdges)).run();
    }

    function zoomIn() {
        if (!cy) return;
        cy.animate({ zoom: { level: Math.min(2.8, cy.zoom() * 1.25), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 160 });
    }

    function zoomOut() {
        if (!cy) return;
        cy.animate({ zoom: { level: Math.max(0.22, cy.zoom() * 0.8), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 160 });
    }

    function fit() {
        if (!cy) return;
        cy.animate({ fit: { eles: cy.elements().not(".hidden-filter"), padding: 42 } }, { duration: 260 });
    }

    function clearHighlight() {
        if (!cy) return;
        cy.elements().removeClass("dimmed highlighted");
    }

    function highlightCluster(clusterId) {
        if (!cy) return;
        clearHighlight();
        if (!clusterId) {
            fit();
            return;
        }
        const members = cy.nodes().filter(n => n.data("clusterId") === clusterId);
        if (members.length === 0) return;
        const branch = members.union(members.predecessors()).union(members.successors());
        cy.elements().addClass("dimmed");
        branch.removeClass("dimmed").addClass("highlighted");
        cy.animate({ fit: { eles: branch, padding: 48 } }, { duration: 340 });
    }

    function exportPng(fileName) {
        if (!cy) return false;
        const bg = isLight() ? "#f8fafc" : "#070b14";
        const dataUrl = cy.png({ full: true, scale: 2, bg });
        if (window.sentinelUtils) {
            window.sentinelUtils.downloadDataUrl(fileName || "sentinel-arbre-causal.png", dataUrl);
        }
        return true;
    }

    function updateTheme() {
        if (!cy) return;
        cy.style(buildStylesheet());
    }

    function destroy() {
        if (cy) {
            try { cy.destroy(); } catch { }
            cy = null;
        }
        dotNetRef = null;
    }

    return {
        render,
        setLayout,
        applyFilter,
        zoomIn,
        zoomOut,
        fit,
        highlightCluster,
        clearHighlight,
        exportPng,
        updateTheme,
        destroy
    };
})();
