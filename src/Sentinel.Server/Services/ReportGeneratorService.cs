using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Services;

public sealed record GeneratedReport(byte[] Content, string ContentType, string FileName);

/// <summary>
/// Générateur de rapports professionnels PDF (QuestPDF) et JSON (exigence F10, doc §10.1-6) :
/// synthèse exécutive, alertes avec justification complète, référentiel MITRE ATT&amp;CK,
/// actions/réversibilité, clusters corrélés et vérification d'intégrité cryptographique des journaux.
/// </summary>
public sealed class ReportGeneratorService
{
    private const string NavyPrimary = "#0F172A";
    private const string SlateAccent = "#1E293B";
    private const string BlueAccent = "#1D4ED8";
    private const string BorderLight = "#CBD5E1";
    private const string BgMuted = "#F8FAFC";
    private const string TextMuted = "#475569";

    static ReportGeneratorService()
    {
        QuestPDF.Settings.License = LicenseType.Community;
    }

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly DashboardService _dashboard;
    private readonly IntegrityVerifier _integrityVerifier;

    public ReportGeneratorService(
        IDbContextFactory<SentinelDbContext> dbFactory,
        DashboardService dashboard,
        IntegrityVerifier integrityVerifier)
    {
        _dbFactory = dbFactory;
        _dashboard = dashboard;
        _integrityVerifier = integrityVerifier;
    }

    public async Task<GeneratedReport> GenerateGlobalReportAsync(
        DateTimeOffset from,
        DateTimeOffset to,
        ReportFormat format,
        string? hostId,
        CancellationToken ct = default)
    {
        var fromMs = from.ToUnixTimeMilliseconds();
        var toMs = to.ToUnixTimeMilliseconds();
        var now = DateTimeOffset.UtcNow;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var alertsQuery = db.Alerts.AsNoTracking()
            .Where(a => a.CreatedAtUnixMs >= fromMs && a.CreatedAtUnixMs <= toMs);
        var clustersQuery = db.Clusters.AsNoTracking()
            .Where(c => c.LastSeenUnixMs >= fromMs && c.LastSeenUnixMs <= toMs);
        var actionsQuery = db.ActionTickets.AsNoTracking()
            .Where(t => t.CreatedAtUnixMs >= fromMs && t.CreatedAtUnixMs <= toMs);
        var eventsQuery = db.Events.AsNoTracking()
            .Where(e => e.TimestampUnixMs >= fromMs && e.TimestampUnixMs <= toMs);

        if (!string.IsNullOrWhiteSpace(hostId))
        {
            var h = hostId.Trim();
            alertsQuery = alertsQuery.Where(a => a.HostId == h);
            clustersQuery = clustersQuery.Where(c => c.HostId == h);
            actionsQuery = actionsQuery.Where(t => t.HostId == h);
            eventsQuery = eventsQuery.Where(e => e.HostId == h);
        }

        var alerts = await alertsQuery.OrderByDescending(a => a.Score).ThenByDescending(a => a.CreatedAtUnixMs).Take(200).ToListAsync(ct).ConfigureAwait(false);
        var clusters = await clustersQuery.OrderByDescending(c => c.Score).ThenByDescending(c => c.LastSeenUnixMs).Take(100).ToListAsync(ct).ConfigureAwait(false);
        var actions = await actionsQuery.OrderByDescending(t => t.CreatedAtUnixMs).Take(200).ToListAsync(ct).ConfigureAwait(false);
        var eventCount = await eventsQuery.LongCountAsync(ct).ConfigureAwait(false);
        var summary = await _dashboard.GetSummaryAsync(ct).ConfigureAwait(false);
        var integrity = await _integrityVerifier.VerifyAllAsync(ct).ConfigureAwait(false);

        // Référentiel MITRE ATT&CK agrégé sur toutes les alertes et clusters de la période
        var mitreIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in alerts)
        {
            foreach (var m in a.ToDto().MitreTechniques) mitreIds.Add(m);
        }
        foreach (var c in clusters)
        {
            foreach (var m in c.ToDto().MitreTechniques) mitreIds.Add(m);
        }
        var mitreInfos = mitreIds
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .Select(MitreCatalog.GetOrDefault)
            .ToArray();

        var stamp = now.ToString("yyyyMMdd-HHmm");

        if (format == ReportFormat.Json)
        {
            var payload = new
            {
                GeneratedAt = now,
                Period = new { From = from, To = to },
                HostFilter = string.IsNullOrWhiteSpace(hostId) ? null : hostId.Trim(),
                GlobalSecurityScore = summary.GlobalSecurityScore,
                OperatingMode = summary.Mode,
                TotalEventsInPeriod = eventCount,
                Integrity = integrity,
                Alerts = alerts.Select(a => new
                {
                    Summary = a.ToDto(),
                    a.Justification
                }),
                MitreTechniques = mitreInfos,
                Actions = actions.Select(t => t.ToDto()),
                Clusters = clusters.Select(c => c.ToDto())
            };

            var prettyOptions = SentinelJson.Create();
            prettyOptions.WriteIndented = true;
            var jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, prettyOptions));
            return new GeneratedReport(jsonBytes, "application/json; charset=utf-8", $"sentinel-rapport-{stamp}.json");
        }

        var pdfBytes = BuildGlobalPdf(now, from, to, hostId, summary, eventCount, alerts, clusters, actions, mitreInfos, integrity);
        return new GeneratedReport(pdfBytes, "application/pdf", $"sentinel-rapport-{stamp}.pdf");
    }

    public async Task<GeneratedReport?> GenerateAlertReportAsync(
        Guid alertId,
        ReportFormat format,
        CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var alert = await db.Alerts
            .AsNoTracking()
            .Include(a => a.AlertEvents)
            .Include(a => a.History)
            .FirstOrDefaultAsync(a => a.Id == alertId, ct)
            .ConfigureAwait(false);

        if (alert is null)
            return null;

        var eventIds = alert.AlertEvents.Select(ae => ae.EventId).Distinct().ToList();
        var events = eventIds.Count == 0
            ? new List<EventEntity>()
            : await db.Events
                .AsNoTracking()
                .Where(e => eventIds.Contains(e.Id))
                .OrderBy(e => e.TimestampUnixMs)
                .ToListAsync(ct)
                .ConfigureAwait(false);

        ClusterEntity? cluster = null;
        if (alert.ClusterId is { } cid)
        {
            cluster = await db.Clusters
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == cid, ct)
                .ConfigureAwait(false);
        }

        var actions = await db.ActionTickets
            .AsNoTracking()
            .Where(t => t.AlertId == alert.Id)
            .OrderBy(t => t.CreatedAtUnixMs)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var pendingActions = actions.Count(t => t.Status is ActionStatus.Proposed or ActionStatus.Pending);
        var alertDto = alert.ToDto(pendingActions);
        var detail = new AlertDetailDto(
            alertDto,
            alert.Justification,
            events.Select(e => e.ToDto()).ToArray(),
            cluster?.ToDto(),
            actions.Select(t => t.ToDto()).ToArray(),
            alert.History.OrderBy(h => h.Timestamp).Select(h => h.ToDto()).ToArray());

        var mitreInfos = alertDto.MitreTechniques
            .OrderBy(m => m, StringComparer.OrdinalIgnoreCase)
            .Select(MitreCatalog.GetOrDefault)
            .ToArray();

        var integrity = await _integrityVerifier.VerifyAllAsync(ct).ConfigureAwait(false);
        var shortId = alert.Id.ToString("N")[..8];

        if (format == ReportFormat.Json)
        {
            var payload = new
            {
                GeneratedAt = now,
                Detail = detail,
                MitreTechniques = mitreInfos,
                Integrity = integrity
            };
            var prettyOptions = SentinelJson.Create();
            prettyOptions.WriteIndented = true;
            var jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, prettyOptions));
            return new GeneratedReport(jsonBytes, "application/json; charset=utf-8", $"sentinel-alerte-{shortId}.json");
        }

        var pdfBytes = BuildAlertPdf(now, detail, mitreInfos, integrity);
        return new GeneratedReport(pdfBytes, "application/pdf", $"sentinel-alerte-{shortId}.pdf");
    }

    private static byte[] BuildGlobalPdf(
        DateTimeOffset generatedAt,
        DateTimeOffset from,
        DateTimeOffset to,
        string? hostId,
        DashboardSummaryDto summary,
        long eventCount,
        List<AlertEntity> alerts,
        List<ClusterEntity> clusters,
        List<ActionTicketEntity> actions,
        MitreTechniqueInfo[] mitreInfos,
        IReadOnlyList<IntegrityReportDto> integrity)
    {
        return Document.Create(document =>
        {
            document.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(1.4f, Unit.Centimetre);
                page.DefaultTextStyle(x => x.FontSize(9f).FontColor("#1E293B"));

                page.Header().Element(c => RenderBanner(
                    c,
                    "SENTINEL — Rapport de Sécurité et de Corrélation",
                    $"Période : {from:dd/MM/yyyy HH:mm} UTC → {to:dd/MM/yyyy HH:mm} UTC   |   Périmètre : {(string.IsNullOrWhiteSpace(hostId) ? "Tous les postes" : hostId)}",
                    generatedAt));

                page.Content().PaddingVertical(10).Column(col =>
                {
                    col.Spacing(12);

                    // 1. Synthèse exécutive
                    col.Item().Element(c => RenderSectionTitle(c, "1. Synthèse exécutive"));
                    col.Item().Row(row =>
                    {
                        row.Spacing(8);
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Score global", $"{summary.GlobalSecurityScore}/100", ScoreHexColor(100 - summary.GlobalSecurityScore)));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Alertes (période)", alerts.Count.ToString(), alerts.Count > 0 ? "#B91C1C" : "#15803D"));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Clusters corrélés", clusters.Count.ToString(), "#1D4ED8"));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Actions / blocages", actions.Count.ToString(), "#B45309"));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Événements", eventCount.ToString(), "#334155"));
                    });

                    // 2. Intégrité cryptographique des journaux
                    col.Item().Element(c => RenderSectionTitle(c, "2. Intégrité cryptographique des journaux (chaîne SHA-256)"));
                    col.Item().Element(c => RenderIntegrityTable(c, integrity));

                    // 3. Alertes détaillées avec justification
                    col.Item().Element(c => RenderSectionTitle(c, $"3. Alertes de sécurité et justifications ({alerts.Count})"));
                    if (alerts.Count == 0)
                    {
                        col.Item().Text("Aucune alerte enregistrée sur la période sélectionnée.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        foreach (var a in alerts.Take(40))
                        {
                            var dto = a.ToDto();
                            col.Item().Border(0.5f).BorderColor(BorderLight).Background(BgMuted).Padding(8).Column(card =>
                            {
                                card.Spacing(3);
                                card.Item().Row(r =>
                                {
                                    r.RelativeItem().Text(a.Title).SemiBold().FontSize(9.5f).FontColor(NavyPrimary);
                                    r.ConstantItem(95).AlignRight().Text($"{ThreatLevels.Label(a.Level).ToUpperInvariant()} ({a.Score}/100)")
                                        .Bold().FontColor(LevelHexColor(a.Level));
                                });
                                card.Item().Text($"Poste : {a.HostId}  |  Utilisateur : {a.UserId}  |  Statut : {ActionPolicyHelper.AlertStatusLabel(a.Status)}  |  Événements : {a.EventCount}  |  Créée le : {a.CreatedAt:dd/MM/yyyy HH:mm} UTC")
                                    .FontSize(8f).FontColor(TextMuted);
                                card.Item().Text(t =>
                                {
                                    t.Span("Justification : ").SemiBold();
                                    t.Span(a.Justification);
                                });
                                if (dto.MitreTechniques.Count > 0)
                                {
                                    card.Item().Text($"Techniques MITRE ATT&CK : {string.Join(", ", dto.MitreTechniques)}")
                                        .FontSize(8f).FontColor(BlueAccent);
                                }
                            });
                        }
                    }

                    // 4. Référentiel MITRE ATT&CK
                    col.Item().Element(c => RenderSectionTitle(c, $"4. Techniques MITRE ATT&CK observées ({mitreInfos.Length})"));
                    if (mitreInfos.Length == 0)
                    {
                        col.Item().Text("Aucune technique MITRE ATT&CK référencée sur la période.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        col.Item().Element(c => RenderMitreTable(c, mitreInfos));
                    }

                    // 5. Actions de réponse et réversibilité
                    col.Item().Element(c => RenderSectionTitle(c, $"5. Actions de réponse et réversibilité ({actions.Count})"));
                    if (actions.Count == 0)
                    {
                        col.Item().Text("Aucune action de réponse créée sur la période.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        col.Item().Element(c => RenderActionsTable(c, actions.Select(t => t.ToDto()).ToArray()));
                    }

                    // 6. Clusters de corrélation
                    col.Item().Element(c => RenderSectionTitle(c, $"6. Clusters de corrélation ({clusters.Count})"));
                    if (clusters.Count == 0)
                    {
                        col.Item().Text("Aucun cluster de corrélation sur la période.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        col.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.RelativeColumn(1.4f);
                                cols.ConstantColumn(55);
                                cols.RelativeColumn(1.5f);
                                cols.ConstantColumn(45);
                                cols.RelativeColumn(3.2f);
                            });

                            table.Header(h =>
                            {
                                RenderHeaderCell(h.Cell(), "Poste");
                                RenderHeaderCell(h.Cell(), "Score");
                                RenderHeaderCell(h.Cell(), "Menace / Chaîne");
                                RenderHeaderCell(h.Cell(), "Évts");
                                RenderHeaderCell(h.Cell(), "Justification");
                            });

                            foreach (var cl in clusters.Take(35))
                            {
                                RenderBodyCell(table.Cell(), cl.HostId);
                                RenderBodyCell(table.Cell(), $"{cl.Score}/100 (max {cl.MaxEventScore})");
                                RenderBodyCell(table.Cell(), string.IsNullOrWhiteSpace(cl.ChainName)
                                    ? ActionPolicyHelper.ThreatTypeLabel(cl.DominantType)
                                    : $"{cl.ChainName} ({cl.ChainStepsMatched}/{cl.ChainTotalSteps})");
                                RenderBodyCell(table.Cell(), cl.EventCount.ToString());
                                RenderBodyCell(table.Cell(), cl.Justification);
                            }
                        });
                    }
                });

                page.Footer().Element(c => RenderFooter(c, generatedAt));
            });
        }).GeneratePdf();
    }

    private static byte[] BuildAlertPdf(
        DateTimeOffset generatedAt,
        AlertDetailDto detail,
        MitreTechniqueInfo[] mitreInfos,
        IReadOnlyList<IntegrityReportDto> integrity)
    {
        var alert = detail.Alert;
        return Document.Create(document =>
        {
            document.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(1.4f, Unit.Centimetre);
                page.DefaultTextStyle(x => x.FontSize(9f).FontColor("#1E293B"));

                page.Header().Element(c => RenderBanner(
                    c,
                    $"SENTINEL — Fiche d'Alerte #{alert.Id.ToString("N")[..8].ToUpperInvariant()}",
                    alert.Title,
                    generatedAt));

                page.Content().PaddingVertical(10).Column(col =>
                {
                    col.Spacing(11);

                    // Métadonnées & KPI
                    col.Item().Row(row =>
                    {
                        row.Spacing(8);
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Score / Niveau", $"{alert.Score}/100 ({ThreatLevels.Label(alert.Level)})", LevelHexColor(alert.Level)));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Statut", ActionPolicyHelper.AlertStatusLabel(alert.Status), BlueAccent));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Poste / Utilisateur", $"{alert.HostId} / {alert.UserId}", SlateAccent));
                        row.RelativeItem().Element(c => RenderKpiCard(c, "Événements liés", detail.Events.Count.ToString(), SlateAccent));
                    });

                    // Justification complète
                    col.Item().Element(c => RenderSectionTitle(c, "1. Synthèse et justification de la décision"));
                    col.Item().Border(0.5f).BorderColor(BorderLight).Background(BgMuted).Padding(8).Column(box =>
                    {
                        box.Spacing(4);
                        box.Item().Text(alert.Summary).SemiBold();
                        box.Item().Text(detail.Justification);
                    });

                    // Cluster associé
                    if (detail.Cluster is { } cluster)
                    {
                        col.Item().Element(c => RenderSectionTitle(c, "2. Cluster de corrélation associé"));
                        col.Item().Border(0.5f).BorderColor(BorderLight).Padding(8).Column(box =>
                        {
                            box.Spacing(3);
                            box.Item().Text($"Score corrélé : {cluster.Score}/100 (score individuel max : {cluster.MaxEventScore}/100)  |  Escalade précoce : {(cluster.Escalated ? "Oui" : "Non")}").SemiBold();
                            if (!string.IsNullOrWhiteSpace(cluster.ChainName))
                            {
                                box.Item().Text($"Chaîne d'attaque : {cluster.ChainName} ({cluster.ChainStepsMatched}/{cluster.ChainTotalSteps} étapes)").FontColor(BlueAccent);
                            }
                            if (cluster.ContextKeys.Count > 0)
                            {
                                box.Item().Text($"Clés de contexte partagées : {string.Join(", ", cluster.ContextKeys)}").FontSize(8.5f).FontColor(TextMuted);
                            }
                            box.Item().Text(cluster.Justification);
                        });
                    }

                    // Techniques MITRE
                    if (mitreInfos.Length > 0)
                    {
                        col.Item().Element(c => RenderSectionTitle(c, "3. Techniques MITRE ATT&CK"));
                        col.Item().Element(c => RenderMitreTable(c, mitreInfos));
                    }

                    // Chronologie des événements
                    col.Item().Element(c => RenderSectionTitle(c, $"4. Chronologie des événements ({detail.Events.Count})"));
                    if (detail.Events.Count == 0)
                    {
                        col.Item().Text("Aucun événement lié.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        col.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(82);
                                cols.ConstantColumn(65);
                                cols.RelativeColumn(1.4f);
                                cols.ConstantColumn(40);
                                cols.RelativeColumn(2.4f);
                            });

                            table.Header(h =>
                            {
                                RenderHeaderCell(h.Cell(), "Horodatage UTC");
                                RenderHeaderCell(h.Cell(), "Catégorie");
                                RenderHeaderCell(h.Cell(), "Type / Sujet");
                                RenderHeaderCell(h.Cell(), "Score");
                                RenderHeaderCell(h.Cell(), "Justification");
                            });

                            foreach (var e in detail.Events.Take(60))
                            {
                                RenderBodyCell(table.Cell(), e.Timestamp.ToString("dd/MM HH:mm:ss"));
                                RenderBodyCell(table.Cell(), e.Category.ToString());
                                RenderBodyCell(table.Cell(), $"{e.EventType}\n{e.Subject}");
                                RenderBodyCell(table.Cell(), e.Score.ToString());
                                RenderBodyCell(table.Cell(), e.Justification);
                            }
                        });
                    }

                    // Actions
                    col.Item().Element(c => RenderSectionTitle(c, $"5. Actions de réponse et réversibilité ({detail.Actions.Count})"));
                    if (detail.Actions.Count == 0)
                    {
                        col.Item().Text("Aucune action associée.").Italic().FontColor(TextMuted);
                    }
                    else
                    {
                        col.Item().Element(c => RenderActionsTable(c, detail.Actions));
                    }

                    // Historique
                    col.Item().Element(c => RenderSectionTitle(c, $"6. Historique de traitement ({detail.History.Count})"));
                    if (detail.History.Count > 0)
                    {
                        col.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(95);
                                cols.ConstantColumn(85);
                                cols.ConstantColumn(95);
                                cols.RelativeColumn();
                            });

                            table.Header(h =>
                            {
                                RenderHeaderCell(h.Cell(), "Date UTC");
                                RenderHeaderCell(h.Cell(), "Acteur");
                                RenderHeaderCell(h.Cell(), "Action");
                                RenderHeaderCell(h.Cell(), "Commentaire");
                            });

                            foreach (var h in detail.History)
                            {
                                RenderBodyCell(table.Cell(), h.Timestamp.ToString("dd/MM/yyyy HH:mm:ss"));
                                RenderBodyCell(table.Cell(), h.Actor);
                                RenderBodyCell(table.Cell(), h.Action);
                                RenderBodyCell(table.Cell(), h.Comment ?? "—");
                            }
                        });
                    }

                    // Intégrité
                    col.Item().Element(c => RenderSectionTitle(c, "7. Intégrité des journaux"));
                    col.Item().Element(c => RenderIntegrityTable(c, integrity));
                });

                page.Footer().Element(c => RenderFooter(c, generatedAt));
            });
        }).GeneratePdf();
    }

    private static void RenderBanner(IContainer container, string title, string subtitle, DateTimeOffset generatedAt)
    {
        container.Background(NavyPrimary).Padding(12).Row(row =>
        {
            row.RelativeItem().Column(col =>
            {
                col.Item().Text(title).FontSize(13f).Bold().FontColor(Colors.White);
                col.Item().PaddingTop(2).Text(subtitle).FontSize(8.5f).FontColor("#CBD5E1");
            });
            row.ConstantItem(115).AlignRight().AlignMiddle().Column(col =>
            {
                col.Item().AlignRight().Text("Généré le").FontSize(7.5f).FontColor("#94A3B8");
                col.Item().AlignRight().Text($"{generatedAt:dd/MM/yyyy HH:mm} UTC").FontSize(8.5f).SemiBold().FontColor(Colors.White);
            });
        });
    }

    private static void RenderSectionTitle(IContainer container, string title)
    {
        container.BorderBottom(1f).BorderColor(BlueAccent).PaddingBottom(3)
            .Text(title).FontSize(10.5f).Bold().FontColor(NavyPrimary);
    }

    private static void RenderKpiCard(IContainer container, string label, string value, string accentHex)
    {
        container.Border(0.5f).BorderColor(BorderLight).Background(BgMuted).Padding(7).Column(col =>
        {
            col.Item().Text(label).FontSize(7.5f).FontColor(TextMuted);
            col.Item().PaddingTop(2).Text(value).FontSize(11f).Bold().FontColor(accentHex);
        });
    }

    private static void RenderIntegrityTable(IContainer container, IReadOnlyList<IntegrityReportDto> reports)
    {
        container.Table(table =>
        {
            table.ColumnsDefinition(cols =>
            {
                cols.RelativeColumn(1.2f);
                cols.RelativeColumn(1.4f);
                cols.ConstantColumn(95);
                cols.RelativeColumn(1.4f);
            });

            table.Header(h =>
            {
                RenderHeaderCell(h.Cell(), "Journal");
                RenderHeaderCell(h.Cell(), "Statut");
                RenderHeaderCell(h.Cell(), "Entrées vérifiées");
                RenderHeaderCell(h.Cell(), "Première anomalie");
            });

            foreach (var r in reports)
            {
                RenderBodyCell(table.Cell(), r.Scope.Equals("audit", StringComparison.OrdinalIgnoreCase) ? "Journal d'audit" : "Journal d'événements");
                table.Cell().BorderBottom(0.5f).BorderColor(BorderLight).Padding(4)
                    .Text(r.Valid ? "INTÈGRE (SHA-256 valide)" : "ALTÉRATION DÉTECTÉE")
                    .Bold().FontColor(r.Valid ? "#15803D" : "#B91C1C");
                RenderBodyCell(table.Cell(), r.CheckedEntries.ToString());
                RenderBodyCell(table.Cell(), r.FirstBrokenId?.ToString() ?? "Aucune");
            }
        });
    }

    private static void RenderMitreTable(IContainer container, MitreTechniqueInfo[] infos)
    {
        container.Table(table =>
        {
            table.ColumnsDefinition(cols =>
            {
                cols.ConstantColumn(65);
                cols.RelativeColumn(1.3f);
                cols.RelativeColumn(1.1f);
                cols.RelativeColumn(2.6f);
            });

            table.Header(h =>
            {
                RenderHeaderCell(h.Cell(), "ID");
                RenderHeaderCell(h.Cell(), "Technique");
                RenderHeaderCell(h.Cell(), "Tactique");
                RenderHeaderCell(h.Cell(), "Explication");
            });

            foreach (var m in infos)
            {
                table.Cell().BorderBottom(0.5f).BorderColor(BorderLight).Padding(4).Text(m.Id).Bold().FontColor(BlueAccent);
                RenderBodyCell(table.Cell(), m.Name);
                RenderBodyCell(table.Cell(), m.Tactic);
                RenderBodyCell(table.Cell(), m.Description);
            }
        });
    }

    private static void RenderActionsTable(IContainer container, IReadOnlyList<ActionTicketDto> actions)
    {
        container.Table(table =>
        {
            table.ColumnsDefinition(cols =>
            {
                cols.RelativeColumn(1.3f);
                cols.RelativeColumn(1.4f);
                cols.RelativeColumn(1.1f);
                cols.ConstantColumn(55);
                cols.RelativeColumn(2.0f);
            });

            table.Header(h =>
            {
                RenderHeaderCell(h.Cell(), "Action");
                RenderHeaderCell(h.Cell(), "Cible / Poste");
                RenderHeaderCell(h.Cell(), "Statut");
                RenderHeaderCell(h.Cell(), "Réversible");
                RenderHeaderCell(h.Cell(), "Justification / Résultat");
            });

            foreach (var a in actions.Take(50))
            {
                RenderBodyCell(table.Cell(), ActionPolicyHelper.ActionTypeLabel(a.Type));
                RenderBodyCell(table.Cell(), $"{a.Target}\n({a.HostId})");
                RenderBodyCell(table.Cell(), ActionPolicyHelper.ActionStatusLabel(a.Status));
                RenderBodyCell(table.Cell(), a.Reversible ? "Oui" : "Non");
                RenderBodyCell(table.Cell(), string.IsNullOrWhiteSpace(a.ResultMessage) ? a.Rationale : $"{a.Rationale} — {a.ResultMessage}");
            }
        });
    }

    private static void RenderHeaderCell(IContainer cell, string text)
    {
        cell.Background(SlateAccent).Padding(5).Text(text).SemiBold().FontSize(8.5f).FontColor(Colors.White);
    }

    private static void RenderBodyCell(IContainer cell, string text)
    {
        cell.BorderBottom(0.5f).BorderColor(BorderLight).Padding(4).Text(text ?? string.Empty).FontSize(8.2f);
    }

    private static void RenderFooter(IContainer container, DateTimeOffset generatedAt)
    {
        container.BorderTop(0.5f).BorderColor(BorderLight).PaddingTop(4).Row(row =>
        {
            row.RelativeItem().Text($"SENTINEL — Document de sécurité généré localement le {generatedAt:dd/MM/yyyy HH:mm} UTC (aucune donnée transmise sur Internet)")
                .FontSize(7.5f).FontColor(TextMuted);
            row.ConstantItem(70).AlignRight().Text(t =>
            {
                t.DefaultTextStyle(s => s.FontSize(7.5f).FontColor(TextMuted));
                t.Span("Page ");
                t.CurrentPageNumber();
                t.Span(" / ");
                t.TotalPages();
            });
        });
    }

    private static string LevelHexColor(ThreatLevel level) => level switch
    {
        ThreatLevel.Critical => "#B91C1C",
        ThreatLevel.High => "#C2410C",
        ThreatLevel.Moderate => "#B45309",
        ThreatLevel.Low => "#1D4ED8",
        _ => "#475569"
    };

    private static string ScoreHexColor(int risk) =>
        risk >= 70 ? "#B91C1C" : risk >= 40 ? "#B45309" : "#15803D";
}
