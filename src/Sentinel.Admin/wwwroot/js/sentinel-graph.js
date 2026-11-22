/* SENTINEL Admin — Graphe de corrélation Cytoscape.js local */
window.sentinelGraph = (() => {
    let cy = null;
    let dotNetRef = null;
    let lastContainerId = null;

    const NODE_SHAPES = {
        Threat: "diamond",
        Process: "hexagon",
        File: "round-rectangle",
        Domain: "ellipse",
        Ip: "ellipse",
        Device: "triangle",
        Event: "octagon",
        User: "round-octagon",
        Host: "rectangle"
    };

    const NODE_ACCENTS = {
        Threat: "#ef4444",
        Process: "#8b5cf6",
        File: "#f59e0b",
        Domain: "#06b6d4",
        Ip: "#38bdf8",
        Device: "#f97316",
        Event: "#64748b",
        User: "#10b981",
        Host: "#6366f1"
    };

    const LEVEL_COLORS = {
        Info: "#38bdf8",
        Low: "#06b6d4",
        Moderate: "#f59e0b",
        High: "#f97316",
        Critical: "#ef4444"
    };

    function isLight() {
        return document.documentElement.getAttribute("data-theme") === "light";
    }

    function buildStylesheet() {
        const light = isLight();
        const labelColor = light ? "#0f172a" : "#e2e8f0";
        const labelBg = light ? "rgba(255, 255, 255, 0.88)" : "rgba(7, 11, 20, 0.86)";
        const nodeBg = light ? "#ffffff" : "#111b2e";
        const edgeColor = light ? "rgba(51, 65, 85, 0.55)" : "rgba(148, 163, 184, 0.48)";
        const edgeLabelColor = light ? "#475569" : "#94a3b8";

        return [
            {
                selector: "node[kind = 'cluster']",
                style: {
                    "shape": "round-rectangle",
                    "background-color": "data(clusterBg)",
                    "background-opacity": light ? 0.08 : 0.12,
                    "border-color": "data(borderColor)",
                    "border-width": 2,
                    "border-style": "dashed",
                    "padding": "20px",
                    "label": "data(label)",
                    "text-valign": "top",
                    "text-halign": "center",
                    "text-margin-y": -6,
                    "color": "data(borderColor)",
                    "font-size": 11,
                    "font-weight": 700,
                    "font-family": "Segoe UI, sans-serif"
                }
            },
            {
                selector: "node[kind = 'entity']",
                style: {
                    "shape": "data(shape)",
                    "width": "data(size)",
                    "height": "data(size)",
                    "background-color": nodeBg,
                    "border-color": "data(borderColor)",
                    "border-width": "data(borderWidth)",
                    "label": "data(shortLabel)",
                    "color": labelColor,
                    "font-size": 10,
                    "font-weight": 600,
                    "font-family": "Segoe UI, sans-serif",
                    "text-valign": "bottom",
                    "text-halign": "center",
                    "text-margin-y": 6,
                    "text-background-color": labelBg,
                    "text-background-opacity": 0.9,
                    "text-background-padding": "3px",
                    "text-background-shape": "roundrectangle",
                    "text-max-width": "120px",
                    "text-wrap": "ellipsis",
                    "underlay-color": "data(borderColor)",
                    "underlay-padding": "data(haloPad)",
                    "underlay-opacity": "data(haloOpacity)",
                    "underlay-shape": "ellipse",
                    "overlay-padding": 6
                }
            },
            {
                selector: "node[kind = 'entity']:selected",
                style: {
                    "border-width": 4,
                    "background-color": "data(borderColor)",
                    "color": light ? "#0f172a" : "#ffffff",
                    "z-index": 99
                }
            },
            {
                selector: "edge",
                style: {
                    "width": "data(width)",
                    "line-color": edgeColor,
                    "target-arrow-color": edgeColor,
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier",
                    "arrow-scale": 0.9,
                    "label": "data(label)",
                    "font-size": 8.5,
                    "font-family": "Consolas, monospace",
                    "color": edgeLabelColor,
                    "text-rotation": "autorotate",
                    "text-background-color": labelBg,
                    "text-background-opacity": 0.88,
                    "text-background-padding": "2px",
                    "text-opacity": 0.85
                }
            },
            {
                selector: "edge[edgeType = 'Sequence']",
                style: {
                    "line-style": "dashed",
                    "line-dash-pattern": [6, 3],
                    "line-color": "#ef4444",
                    "target-arrow-color": "#ef4444",
                    "width": 2.6,
                    "color": "#ef4444",
                    "text-opacity": 1
                }
            },
            {
                selector: "edge[edgeType = 'Spawned'], edge[edgeType = 'OpenedUrl'], edge[edgeType = 'CopiedFromClipboard']",
                style: {
                    "line-color": "#06b6d4",
                    "target-arrow-color": "#06b6d4"
                }
            },
            {
                selector: "edge[edgeType = 'Wrote'], edge[edgeType = 'ConnectedTo']",
                style: {
                    "line-color": "#8b5cf6",
                    "target-arrow-color": "#8b5cf6"
                }
            },
            {
                selector: "edge:selected",
                style: {
                    "width": 3.5,
                    "line-color": "#f59e0b",
                    "target-arrow-color": "#f59e0b",
                    "z-index": 90
                }
            },
            {
                selector: ".dimmed",
                style: {
                    "opacity": 0.16
                }
            },
            {
                selector: ".highlighted",
                style: {
                    "opacity": 1,
                    "z-index": 50
                }
            }
        ];
    }

    function layoutOptions(name) {
        switch (name) {
            case "breadthfirst":
                return { name: "breadthfirst", directed: true, padding: 36, spacingFactor: 1.35, animate: true, animationDuration: 450 };
            case "concentric":
                return {
                    name: "concentric",
                    padding: 36,
                    animate: true,
                    animationDuration: 450,
                    concentric: n => n.data("score") || 10,
                    levelWidth: () => 20
                };
            case "circle":
                return { name: "circle", padding: 36, animate: true, animationDuration: 450 };
            case "grid":
                return { name: "grid", padding: 36, animate: true, animationDuration: 450 };
            case "cose":
            default:
                return {
                    name: "cose",
                    padding: 40,
                    animate: true,
                    animationDuration: 550,
                    nodeRepulsion: () => 9000,
                    idealEdgeLength: () => 115,
                    edgeElasticity: () => 120,
                    nestingFactor: 1.2
                };
        }
    }

    function render(containerId, payload, layoutName, groupClusters, netRef) {
        if (typeof cytoscape === "undefined") return;
        const container = document.getElementById(containerId);
        if (!container) return;

        destroy();
        lastContainerId = containerId;
        dotNetRef = netRef;

        const elements = [];
        const clusterIds = new Set();

        if (groupClusters && payload && Array.isArray(payload.clusters)) {
            for (const c of payload.clusters) {
                const cid = `cluster:${c.id}`;
                clusterIds.add(c.id);
                const color = LEVEL_COLORS[c.level] || "#8b5cf6";
                const title = c.chainName
                    ? `${c.chainName} • Score ${c.score}`
                    : `Cluster ${String(c.id).substring(0, 6)} • Score ${c.score}`;
                elements.push({
                    group: "nodes",
                    data: {
                        id: cid,
                        rawClusterId: c.id,
                        kind: "cluster",
                        label: title,
                        borderColor: color,
                        clusterBg: color,
                        score: c.score || 50
                    }
                });
            }
        }

        const nodeIdSet = new Set();
        if (payload && Array.isArray(payload.nodes)) {
            for (const n of payload.nodes) {
                nodeIdSet.add(n.id);
                const levelColor = LEVEL_COLORS[n.level] || NODE_ACCENTS[n.type] || "#06b6d4";
                const borderColor = (n.score >= 55 || n.type === "Threat") ? levelColor : (NODE_ACCENTS[n.type] || levelColor);
                const size = Math.max(30, Math.min(54, 30 + Math.round((n.score || 0) * 0.24)));
                const shortLabel = n.label && n.label.length > 26 ? `${n.label.substring(0, 24)}…` : (n.label || n.id);
                const nodeData = {
                    id: n.id,
                    kind: "entity",
                    nodeType: n.type,
                    label: n.label || n.id,
                    shortLabel,
                    score: n.score || 0,
                    level: n.level || "Info",
                    clusterId: n.clusterId || null,
                    shape: NODE_SHAPES[n.type] || "ellipse",
                    borderColor,
                    borderWidth: n.score >= 75 ? 3.5 : 2.2,
                    size,
                    haloPad: n.score >= 75 ? 10 : (n.score >= 30 ? 5 : 0),
                    haloOpacity: n.score >= 75 ? 0.28 : (n.score >= 30 ? 0.14 : 0)
                };
                if (groupClusters && n.clusterId && clusterIds.has(n.clusterId)) {
                    nodeData.parent = `cluster:${n.clusterId}`;
                }
                elements.push({ group: "nodes", data: nodeData });
            }
        }

        if (payload && Array.isArray(payload.edges)) {
            for (const e of payload.edges) {
                if (!nodeIdSet.has(e.source) || !nodeIdSet.has(e.target)) continue;
                elements.push({
                    group: "edges",
                    data: {
                        id: e.id,
                        source: e.source,
                        target: e.target,
                        edgeType: e.type,
                        weight: e.weight || 0.5,
                        width: Math.max(1.4, Math.min(3.4, 1.3 + (e.weight || 0.5) * 2.1)),
                        label: e.label || e.type
                    }
                });
            }
        }

        cy = cytoscape({
            container,
            elements,
            style: buildStylesheet(),
            layout: elements.length > 0 ? layoutOptions(layoutName || "cose") : { name: "preset" },
            minZoom: 0.2,
            maxZoom: 3.2
        });

        cy.on("tap", "node[kind = 'entity']", evt => {
            const id = evt.target.data("id");
            if (dotNetRef) dotNetRef.invokeMethodAsync("OnNodeSelected", id);
        });

        cy.on("tap", "node[kind = 'cluster']", evt => {
            const cid = evt.target.data("rawClusterId");
            if (dotNetRef && cid) dotNetRef.invokeMethodAsync("OnClusterSelected", cid);
        });

        cy.on("tap", "edge", evt => {
            const id = evt.target.data("id");
            if (dotNetRef) dotNetRef.invokeMethodAsync("OnEdgeSelected", id);
        });

        cy.on("tap", evt => {
            if (evt.target === cy) {
                clearHighlight();
                if (dotNetRef) dotNetRef.invokeMethodAsync("OnCanvasCleared");
            }
        });
    }

    function setLayout(layoutName) {
        if (!cy) return;
        cy.layout(layoutOptions(layoutName || "cose")).run();
    }

    function zoomIn() {
        if (!cy) return;
        cy.animate({ zoom: { level: Math.min(3.2, cy.zoom() * 1.25), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 180 });
    }

    function zoomOut() {
        if (!cy) return;
        cy.animate({ zoom: { level: Math.max(0.2, cy.zoom() * 0.8), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 180 });
    }

    function fit() {
        if (!cy) return;
        cy.animate({ fit: { padding: 36 } }, { duration: 280 });
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
        const members = cy.nodes().filter(n => n.data("clusterId") === clusterId || n.data("rawClusterId") === clusterId);
        if (members.length === 0) return;
        const connected = members.union(members.connectedEdges()).union(members.ancestors());
        cy.elements().addClass("dimmed");
        connected.removeClass("dimmed").addClass("highlighted");
        cy.animate({ fit: { eles: connected, padding: 52 } }, { duration: 380 });
    }

    function exportPng(fileName) {
        if (!cy) return false;
        const bg = isLight() ? "#f4f7fb" : "#070b14";
        const dataUrl = cy.png({ full: true, scale: 2, bg });
        if (window.sentinelUtils) {
            window.sentinelUtils.downloadDataUrl(fileName || "sentinel-graphe-correlation.png", dataUrl);
        }
        return true;
    }

    function updateTheme() {
        if (!cy) return;
        cy.style(buildStylesheet());
    }

    function destroy() {
        if (cy) {
            try {
                cy.destroy();
            } catch {
                // Ignoré
            }
            cy = null;
        }
        dotNetRef = null;
        lastContainerId = null;
    }

    return {
        render,
        setLayout,
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
