/* SENTINEL Admin — Graphiques Chart.js locaux adaptés aux thèmes Sombre & Clair */
window.sentinelCharts = (() => {
    const registry = new Map();

    function palette() {
        const isLight = document.documentElement.getAttribute("data-theme") === "light";
        return {
            isLight,
            text: isLight ? "#475569" : "#94a3b8",
            textStrong: isLight ? "#0f172a" : "#f1f5f9",
            grid: isLight ? "rgba(15, 23, 42, 0.08)" : "rgba(148, 163, 184, 0.11)",
            tooltipBg: isLight ? "rgba(15, 23, 42, 0.94)" : "rgba(10, 16, 29, 0.96)",
            tooltipBorder: isLight ? "rgba(148, 163, 184, 0.25)" : "rgba(6, 182, 212, 0.35)",
            cyan: "#06b6d4",
            emerald: "#10b981",
            amber: "#f59e0b",
            crimson: "#ef4444",
            violet: "#8b5cf6"
        };
    }

    function destroyChart(canvasId) {
        const existing = registry.get(canvasId);
        if (existing) {
            try {
                existing.destroy();
            } catch {
                // Ignoré
            }
            registry.delete(canvasId);
        }
    }

    function baseFont() {
        return {
            family: "'Inter', 'Segoe UI Variable', system-ui, -apple-system, sans-serif",
            size: 11
        };
    }

    function renderTimelineChart(canvasId, labels, eventsData, alertsData, maxScoreData) {
        if (typeof Chart === "undefined") return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        destroyChart(canvasId);

        const ctx = canvas.getContext("2d");
        const p = palette();

        const cyanGrad = ctx.createLinearGradient(0, 0, 0, canvas.clientHeight || 260);
        cyanGrad.addColorStop(0, p.isLight ? "rgba(6, 182, 212, 0.28)" : "rgba(6, 182, 212, 0.32)");
        cyanGrad.addColorStop(1, "rgba(6, 182, 212, 0.01)");

        const crimsonGrad = ctx.createLinearGradient(0, 0, 0, canvas.clientHeight || 260);
        crimsonGrad.addColorStop(0, "rgba(239, 68, 68, 0.25)");
        crimsonGrad.addColorStop(1, "rgba(239, 68, 68, 0.0)");

        const chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels || [],
                datasets: [
                    {
                        label: "Événements",
                        data: eventsData || [],
                        borderColor: p.cyan,
                        backgroundColor: cyanGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                        yAxisID: "yEvents"
                    },
                    {
                        label: "Alertes",
                        data: alertsData || [],
                        borderColor: p.crimson,
                        backgroundColor: crimsonGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 3,
                        pointHoverRadius: 6,
                        yAxisID: "yEvents"
                    },
                    {
                        label: "Score max",
                        data: maxScoreData || [],
                        borderColor: p.amber,
                        backgroundColor: "transparent",
                        borderWidth: 2,
                        borderDash: [5, 4],
                        tension: 0.25,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                        yAxisID: "yScore"
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        position: "top",
                        align: "end",
                        labels: {
                            color: p.text,
                            usePointStyle: true,
                            pointStyle: "circle",
                            boxWidth: 8,
                            padding: 16,
                            font: baseFont()
                        }
                    },
                    tooltip: {
                        backgroundColor: p.tooltipBg,
                        borderColor: p.tooltipBorder,
                        borderWidth: 1,
                        titleColor: "#f8fafc",
                        bodyColor: "#e2e8f0",
                        padding: 12,
                        cornerRadius: 10
                    }
                },
                scales: {
                    x: {
                        grid: { color: p.grid, drawBorder: false },
                        ticks: { color: p.text, maxTicksLimit: 10, font: baseFont() }
                    },
                    yEvents: {
                        type: "linear",
                        position: "left",
                        beginAtZero: true,
                        grid: { color: p.grid },
                        ticks: { color: p.text, precision: 0, font: baseFont() },
                        title: { display: true, text: "Volume", color: p.text, font: baseFont() }
                    },
                    yScore: {
                        type: "linear",
                        position: "right",
                        min: 0,
                        max: 100,
                        grid: { drawOnChartArea: false },
                        ticks: { color: p.amber, stepSize: 25, font: baseFont() },
                        title: { display: true, text: "Score (0–100)", color: p.amber, font: baseFont() }
                    }
                }
            }
        });

        registry.set(canvasId, chart);
    }

    function renderDoughnutChart(canvasId, labels, values, colors) {
        if (typeof Chart === "undefined") return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        destroyChart(canvasId);

        const p = palette();
        const chart = new Chart(canvas.getContext("2d"), {
            type: "doughnut",
            data: {
                labels: labels || [],
                datasets: [{
                    data: values || [],
                    backgroundColor: colors || [],
                    borderColor: p.isLight ? "#ffffff" : "#0e1525",
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: p.text,
                            usePointStyle: true,
                            pointStyle: "circle",
                            boxWidth: 8,
                            padding: 12,
                            font: baseFont()
                        }
                    },
                    tooltip: {
                        backgroundColor: p.tooltipBg,
                        borderColor: p.tooltipBorder,
                        borderWidth: 1,
                        titleColor: "#f8fafc",
                        bodyColor: "#e2e8f0",
                        padding: 10,
                        cornerRadius: 8
                    }
                }
            }
        });
        registry.set(canvasId, chart);
    }

    function renderHorizontalBarChart(canvasId, labels, values, colors) {
        if (typeof Chart === "undefined") return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        destroyChart(canvasId);

        const p = palette();
        const chart = new Chart(canvas.getContext("2d"), {
            type: "bar",
            data: {
                labels: labels || [],
                datasets: [{
                    data: values || [],
                    backgroundColor: colors || p.cyan,
                    borderRadius: 6,
                    maxBarThickness: 22
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: p.tooltipBg,
                        borderColor: p.tooltipBorder,
                        borderWidth: 1,
                        titleColor: "#f8fafc",
                        bodyColor: "#e2e8f0",
                        padding: 10,
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: p.grid },
                        ticks: { color: p.text, precision: 0, font: baseFont() }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: p.textStrong, font: baseFont() }
                    }
                }
            }
        });
        registry.set(canvasId, chart);
    }

    function renderEvaluationChart(canvasId, labels, datasets, yAxisTitle) {
        if (typeof Chart === "undefined") return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        destroyChart(canvasId);

        const p = palette();
        const chart = new Chart(canvas.getContext("2d"), {
            type: "bar",
            data: {
                labels: labels || [],
                datasets: (datasets || []).map(ds => ({
                    label: ds.label,
                    data: ds.data,
                    backgroundColor: ds.color,
                    borderRadius: 6,
                    maxBarThickness: 32
                }))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "top",
                        labels: {
                            color: p.text,
                            usePointStyle: true,
                            pointStyle: "rectRounded",
                            padding: 16,
                            font: baseFont()
                        }
                    },
                    tooltip: {
                        backgroundColor: p.tooltipBg,
                        borderColor: p.tooltipBorder,
                        borderWidth: 1,
                        titleColor: "#f8fafc",
                        bodyColor: "#e2e8f0",
                        padding: 10,
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: p.textStrong, font: baseFont() }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: p.grid },
                        ticks: { color: p.text, font: baseFont() },
                        title: {
                            display: Boolean(yAxisTitle),
                            text: yAxisTitle || "",
                            color: p.text,
                            font: baseFont()
                        }
                    }
                }
            }
        });
        registry.set(canvasId, chart);
    }

    function renderEntityActivityChart(canvasId, labels, eventsData, maxScoreData) {
        if (typeof Chart === "undefined") return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        destroyChart(canvasId);

        const ctx = canvas.getContext("2d");
        const p = palette();
        const grad = ctx.createLinearGradient(0, 0, 0, 220);
        grad.addColorStop(0, "rgba(139, 92, 246, 0.34)");
        grad.addColorStop(1, "rgba(139, 92, 246, 0.01)");

        const chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels || [],
                datasets: [
                    {
                        label: "Événements",
                        data: eventsData || [],
                        borderColor: p.violet,
                        backgroundColor: grad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        yAxisID: "yLeft"
                    },
                    {
                        label: "Score max",
                        data: maxScoreData || [],
                        borderColor: p.crimson,
                        backgroundColor: "transparent",
                        borderWidth: 2,
                        borderDash: [4, 4],
                        tension: 0.3,
                        yAxisID: "yRight"
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        position: "top",
                        align: "end",
                        labels: { color: p.text, usePointStyle: true, font: baseFont() }
                    },
                    tooltip: {
                        backgroundColor: p.tooltipBg,
                        borderColor: p.tooltipBorder,
                        borderWidth: 1,
                        titleColor: "#f8fafc",
                        bodyColor: "#e2e8f0",
                        padding: 10,
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: { grid: { color: p.grid }, ticks: { color: p.text, maxTicksLimit: 8, font: baseFont() } },
                    yLeft: { position: "left", beginAtZero: true, grid: { color: p.grid }, ticks: { color: p.text, precision: 0, font: baseFont() } },
                    yRight: { position: "right", min: 0, max: 100, grid: { drawOnChartArea: false }, ticks: { color: p.crimson, stepSize: 25, font: baseFont() } }
                }
            }
        });
        registry.set(canvasId, chart);
    }

    return {
        renderTimelineChart,
        renderDoughnutChart,
        renderHorizontalBarChart,
        renderEvaluationChart,
        renderEntityActivityChart,
        destroyChart
    };
})();
