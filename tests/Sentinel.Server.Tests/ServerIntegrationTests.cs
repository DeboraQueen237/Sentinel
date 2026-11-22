using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;

namespace Sentinel.Server.Tests;

public sealed class ServerIntegrationTests
{
    [Fact]
    public async Task Ping_Is_Anonymous_And_Protected_Routes_Require_Bearer_Token()
    {
        using var factory = new SentinelServerFactory();
        using var client = factory.CreateClient();

        var ping = await client.GetAsync(ApiRoutes.Ping);
        ping.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ping.Content.ReadAsStringAsync()).Should().Be("pong");

        var protectedRoutes = new[]
        {
            ApiRoutes.DashboardSummary,
            ApiRoutes.Alerts,
            ApiRoutes.Events,
            ApiRoutes.Settings,
            ApiRoutes.Audit,
            ApiRoutes.Health
        };

        foreach (var route in protectedRoutes)
        {
            var resp = await client.GetAsync(route);
            resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, $"la route {route} doit exiger un jeton Bearer");
        }
    }

    [Fact]
    public async Task Full_Auth_Lifecycle_Setup_Conflict_Totp_Login_PasswordChange_And_Logout()
    {
        using var factory = new SentinelServerFactory();
        using var client = factory.CreateClient();

        // 1. Statut initial non configuré
        var statusBefore = await client.GetFromJsonAsync<AuthStatusDto>(ApiRoutes.AuthStatus, SentinelJson.Options);
        statusBefore.Should().NotBeNull();
        statusBefore!.IsConfigured.Should().BeFalse();
        statusBefore.Username.Should().BeNull();

        // 2. Premier setup
        const string username = "secadmin";
        const string password = "Strong#Password123!";
        var setupResp = await client.PostAsJsonAsync(ApiRoutes.AuthSetup, new SetupRequest(username, password), SentinelJson.Options);
        setupResp.StatusCode.Should().Be(HttpStatusCode.OK);

        var setup = (await setupResp.Content.ReadFromJsonAsync<SetupResponse>(SentinelJson.Options))!;
        setup.TotpSecret.Should().NotBeNullOrWhiteSpace();
        setup.OtpAuthUri.Should().StartWith($"otpauth://totp/SENTINEL:{username}?secret={setup.TotpSecret}&issuer=SENTINEL");

        // 3. Second setup refusé (409 Conflict)
        var secondSetup = await client.PostAsJsonAsync(ApiRoutes.AuthSetup, new SetupRequest("other", "Another#Pass123!"), SentinelJson.Options);
        secondSetup.StatusCode.Should().Be(HttpStatusCode.Conflict);

        var statusAfter = await client.GetFromJsonAsync<AuthStatusDto>(ApiRoutes.AuthStatus, SentinelJson.Options);
        statusAfter!.IsConfigured.Should().BeTrue();
        statusAfter.Username.Should().Be(username);

        // 4. Échecs de connexion (mauvais mot de passe et mauvais TOTP)
        var validTotp = SentinelServerFactory.ComputeTotp(setup.TotpSecret);
        var badPassword = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest(username, "WrongPassword!", validTotp), SentinelJson.Options);
        badPassword.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var badTotp = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest(username, password, "000000"), SentinelJson.Options);
        badTotp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // 5. Connexion valide
        var loginResp = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest(username, password, validTotp), SentinelJson.Options);
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var login = (await loginResp.Content.ReadFromJsonAsync<LoginResponse>(SentinelJson.Options))!;
        login.Token.Should().NotBeNullOrWhiteSpace();
        login.Username.Should().Be(username);
        login.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);

        // 6. Accès authentifié réussi
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.Token);
        var health = await client.GetFromJsonAsync<SystemHealthDto>(ApiRoutes.Health, SentinelJson.Options);
        health.Should().NotBeNull();
        health!.DatabaseOk.Should().BeTrue();

        // 7. Changement de mot de passe
        const string newPassword = "Updated#Password456!";
        var pwdResp = await client.PostAsJsonAsync(
            ApiRoutes.AuthChangePassword,
            new ChangePasswordRequest(password, newPassword, SentinelServerFactory.ComputeTotp(setup.TotpSecret)),
            SentinelJson.Options);
        pwdResp.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // 8. Logout révoque immédiatement le jeton
        var logoutResp = await client.PostAsync(ApiRoutes.AuthLogout, content: null);
        logoutResp.StatusCode.Should().Be(HttpStatusCode.NoContent);

        var afterLogout = await client.GetAsync(ApiRoutes.Health);
        afterLogout.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // 9. Reconnexion avec le nouveau mot de passe réussit
        client.DefaultRequestHeaders.Authorization = null;
        var reloginResp = await client.PostAsJsonAsync(
            ApiRoutes.AuthLogin,
            new LoginRequest(username, newPassword, SentinelServerFactory.ComputeTotp(setup.TotpSecret)),
            SentinelJson.Options);
        reloginResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Phishing_Scenario_Ingestion_Creates_Cluster_Alert_Graph_And_Dashboard_Metrics()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();
        await ActivateDeterministicModeAsync(client);

        var ingestion = factory.Services.GetRequiredService<EventIngestionService>();
        var events = BuildPhishingChainEvents("WS-PHISH-01", "alice");
        var results = await ingestion.IngestBatchAsync(events);

        results.Should().HaveCount(events.Count);
        results.Any(r => r.Cluster is not null).Should().BeTrue("la chaîne Phishing doit produire un cluster corrélé");

        // Alertes
        var alertsPage = await client.GetFromJsonAsync<PagedResult<AlertDto>>(ApiRoutes.Alerts, SentinelJson.Options);
        alertsPage.Should().NotBeNull();
        alertsPage!.Total.Should().BeGreaterThanOrEqualTo(1);

        var mainAlert = alertsPage.Items[0];
        mainAlert.HostId.Should().Be("WS-PHISH-01");
        mainAlert.ClusterId.Should().NotBeNull();
        mainAlert.Score.Should().BeGreaterThanOrEqualTo(75);
        mainAlert.MitreTechniques.Should().NotBeEmpty();

        var detail = await client.GetFromJsonAsync<AlertDetailDto>(ApiRoutes.Fill(ApiRoutes.AlertById, mainAlert.Id), SentinelJson.Options);
        detail.Should().NotBeNull();
        detail!.Justification.Should().NotBeNullOrWhiteSpace();
        detail.Events.Count.Should().BeGreaterThanOrEqualTo(2);
        detail.Events.Should().BeInAscendingOrder(e => e.Timestamp);
        detail.Cluster.Should().NotBeNull();
        detail.History.Should().NotBeEmpty();

        // Clusters
        var clustersPage = await client.GetFromJsonAsync<PagedResult<ClusterDto>>(ApiRoutes.Clusters, SentinelJson.Options);
        clustersPage!.Total.Should().BeGreaterThanOrEqualTo(1);
        var clusterDto = await client.GetFromJsonAsync<ClusterDto>(ApiRoutes.Fill(ApiRoutes.ClusterById, mainAlert.ClusterId!.Value), SentinelJson.Options);
        clusterDto!.EventCount.Should().BeGreaterThanOrEqualTo(2);

        // Graphe de corrélation
        var graph = await client.GetFromJsonAsync<GraphDto>($"{ApiRoutes.Graph}?hostId=WS-PHISH-01", SentinelJson.Options);
        graph.Should().NotBeNull();
        graph!.Nodes.Should().NotBeEmpty();
        graph.Edges.Should().NotBeEmpty();
        graph.Clusters.Should().NotBeEmpty();
        graph.Nodes.Should().Contain(n => n.Type == GraphNodeType.Event);
        graph.Nodes.Should().Contain(n => n.Type == GraphNodeType.Domain);
        graph.Nodes.Should().Contain(n => n.Type == GraphNodeType.Threat);

        // Tableau de bord (summary + timeline)
        var summary = await client.GetFromJsonAsync<DashboardSummaryDto>(ApiRoutes.DashboardSummary, SentinelJson.Options);
        summary.Should().NotBeNull();
        summary!.GlobalSecurityScore.Should().BeLessThan(100);
        summary.ActiveAlerts.Should().BeGreaterThanOrEqualTo(1);
        summary.EventsLast24h.Should().BeGreaterThanOrEqualTo(events.Count);
        summary.ClustersLast24h.Should().BeGreaterThanOrEqualTo(1);
        summary.RecentAlerts.Should().NotBeEmpty();

        var timeline24h = await client.GetFromJsonAsync<TimeSeriesPointDto[]>($"{ApiRoutes.DashboardTimeline}?range=24h", SentinelJson.Options);
        timeline24h.Should().HaveCount(24);
        timeline24h!.Sum(p => p.Events).Should().BeGreaterThanOrEqualTo(events.Count);

        var timeline7d = await client.GetFromJsonAsync<TimeSeriesPointDto[]>($"{ApiRoutes.DashboardTimeline}?range=7d", SentinelJson.Options);
        timeline7d.Should().HaveCount(28);

        var timeline30d = await client.GetFromJsonAsync<TimeSeriesPointDto[]>($"{ApiRoutes.DashboardTimeline}?range=30d", SentinelJson.Options);
        timeline30d.Should().HaveCount(30);
    }

    [Fact]
    public async Task Admin_Decisions_Approve_Reject_Manual_Action_And_F7_Revert_Work_EndToEnd()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();
        await ActivateDeterministicModeAsync(client);

        var ingestion = factory.Services.GetRequiredService<EventIngestionService>();

        // 1. Génère une alerte sur poste 1 et approuve
        await ingestion.IngestBatchAsync(BuildPhishingChainEvents("WS-DEC-01", "bob"));
        var alerts1 = await client.GetFromJsonAsync<PagedResult<AlertDto>>($"{ApiRoutes.Alerts}?hostId=WS-DEC-01", SentinelJson.Options);
        var alert1 = alerts1!.Items[0];

        var ackResp = await client.PostAsJsonAsync(
            ApiRoutes.Fill(ApiRoutes.AlertAcknowledge, alert1.Id),
            new AlertDecisionRequest("Prise en charge analyste"),
            SentinelJson.Options);
        ackResp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ackResp.Content.ReadFromJsonAsync<AlertDto>(SentinelJson.Options))!.Status.Should().Be(AlertStatus.Acknowledged);

        var approveResp = await client.PostAsJsonAsync(
            ApiRoutes.Fill(ApiRoutes.AlertApprove, alert1.Id),
            new AlertDecisionRequest("Menace confirmée"),
            SentinelJson.Options);
        approveResp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await approveResp.Content.ReadFromJsonAsync<AlertDto>(SentinelJson.Options))!.Status.Should().Be(AlertStatus.Approved);

        // 2. Génère une deuxième alerte sur poste 2 et rejette comme faux positif
        await ingestion.IngestBatchAsync(BuildPhishingChainEvents("WS-DEC-02", "claire"));
        var alerts2 = await client.GetFromJsonAsync<PagedResult<AlertDto>>($"{ApiRoutes.Alerts}?hostId=WS-DEC-02", SentinelJson.Options);
        var alert2 = alerts2!.Items[0];

        var rejectResp = await client.PostAsJsonAsync(
            ApiRoutes.Fill(ApiRoutes.AlertReject, alert2.Id),
            new AlertDecisionRequest("Exercice interne de sensibilisation"),
            SentinelJson.Options);
        rejectResp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await rejectResp.Content.ReadFromJsonAsync<AlertDto>(SentinelJson.Options))!.Status.Should().Be(AlertStatus.FalsePositive);

        // 3. Action manuelle + annulation en 1 clic (Exigence F7)
        var manualResp = await client.PostAsJsonAsync(
            ApiRoutes.Actions,
            new ManualActionRequest("WS-DEC-01", ResponseActionType.BlockDomain, "evil-phish.xyz", "Blocage préventif"),
            SentinelJson.Options);
        manualResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var createdAction = (await manualResp.Content.ReadFromJsonAsync<ActionTicketDto>(SentinelJson.Options))!;
        createdAction.Reversible.Should().BeTrue();
        createdAction.Status.Should().Be(ActionStatus.Pending);

        var revertResp = await client.PostAsync(ApiRoutes.Fill(ApiRoutes.ActionRevert, createdAction.Id), content: null);
        revertResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var reverted = (await revertResp.Content.ReadFromJsonAsync<ActionTicketDto>(SentinelJson.Options))!;
        reverted.Status.Should().Be(ActionStatus.Reverted);
        reverted.RevertedAt.Should().NotBeNull();

        // 4. Si un agent est connecté via AgentCommandHub, le revert d'une action exécutée pousse bien une commande revert=true
        var commandHub = factory.Services.GetRequiredService<AgentCommandHub>();
        using var sub = commandHub.Register("WS-DEC-01");
        var liveManual = await client.PostAsJsonAsync(
            ApiRoutes.Actions,
            new ManualActionRequest("WS-DEC-01", ResponseActionType.BlockIp, "185.220.101.42", "Blocage IP C2"),
            SentinelJson.Options);
        var liveTicket = (await liveManual.Content.ReadFromJsonAsync<ActionTicketDto>(SentinelJson.Options))!;

        var pushedApply = await sub.Reader.ReadAsync();
        pushedApply.CommandId.Should().Be(liveTicket.Id.ToString("D"));
        pushedApply.Revert.Should().BeFalse();

        var liveRevertResp = await client.PostAsync(ApiRoutes.Fill(ApiRoutes.ActionRevert, liveTicket.Id), content: null);
        liveRevertResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var liveReverted = (await liveRevertResp.Content.ReadFromJsonAsync<ActionTicketDto>(SentinelJson.Options))!;
        liveReverted.Status.Should().Be(ActionStatus.RevertPending);

        var pushedRevert = await sub.Reader.ReadAsync();
        pushedRevert.CommandId.Should().Be(liveTicket.Id.ToString("D"));
        pushedRevert.Revert.Should().BeTrue();
    }

    [Fact]
    public async Task Viewing_Entity_Profile_Writes_Mandatory_Audit_Entry_And_Supports_Windows_Paths()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();
        await ActivateDeterministicModeAsync(client);

        var ingestion = factory.Services.GetRequiredService<EventIngestionService>();
        await ingestion.IngestBatchAsync(BuildPhishingChainEvents("WS-AUDIT-01", "david"));

        // Consultation fiche Host
        var hostProfile = await client.GetFromJsonAsync<EntityProfileDto>(
            ApiRoutes.Fill(ApiRoutes.EntityProfile, EntityKind.Host, "WS-AUDIT-01"),
            SentinelJson.Options);
        hostProfile.Should().NotBeNull();
        hostProfile!.Kind.Should().Be(EntityKind.Host);
        hostProfile.Key.Should().Be("WS-AUDIT-01");
        hostProfile.EventCount.Should().BeGreaterThanOrEqualTo(5);

        // Consultation fiche File avec chemin Windows encodé (route catch-all {*key})
        const string winPath = @"C:\Users\david\Downloads\facture.pdf.exe";
        var fileProfile = await client.GetFromJsonAsync<EntityProfileDto>(
            ApiRoutes.Fill(ApiRoutes.EntityProfile, EntityKind.File, winPath),
            SentinelJson.Options);
        fileProfile.Should().NotBeNull();
        fileProfile!.Kind.Should().Be(EntityKind.File);
        fileProfile.Key.Should().Be(winPath);

        // Vérifie la présence des entrées EntityProfileViewed dans le journal d'audit
        var audit = await client.GetFromJsonAsync<PagedResult<AuditEntryDto>>(
            $"{ApiRoutes.Audit}?action=EntityProfileViewed",
            SentinelJson.Options);
        audit.Should().NotBeNull();
        audit!.Items.Should().Contain(e => e.Action == "EntityProfileViewed" && e.Target == "Host:WS-AUDIT-01");
        audit.Items.Should().Contain(e => e.Action == "EntityProfileViewed" && e.Target == $"File:{winPath}");
    }

    [Fact]
    public async Task Reports_Generate_Valid_Pdf_And_Json_And_Evaluation_Metrics_RoundTrip()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();
        await ActivateDeterministicModeAsync(client);

        var ingestion = factory.Services.GetRequiredService<EventIngestionService>();
        await ingestion.IngestBatchAsync(BuildPhishingChainEvents("WS-RPT-01", "emma"));

        var alerts = await client.GetFromJsonAsync<PagedResult<AlertDto>>(ApiRoutes.Alerts, SentinelJson.Options);
        var alertId = alerts!.Items[0].Id;

        // 1. Rapport global PDF
        var globalPdfResp = await client.GetAsync($"{ApiRoutes.ReportGenerate}?format=pdf");
        globalPdfResp.StatusCode.Should().Be(HttpStatusCode.OK);
        globalPdfResp.Content.Headers.ContentType!.MediaType.Should().Be("application/pdf");
        globalPdfResp.Content.Headers.ContentDisposition.Should().NotBeNull();
        var globalPdfBytes = await globalPdfResp.Content.ReadAsByteArrayAsync();
        globalPdfBytes.Length.Should().BeGreaterThan(1500);
        Encoding.ASCII.GetString(globalPdfBytes, 0, 5).Should().Be("%PDF-");

        // 2. Rapport global JSON
        var globalJsonResp = await client.GetAsync($"{ApiRoutes.ReportGenerate}?format=json");
        globalJsonResp.StatusCode.Should().Be(HttpStatusCode.OK);
        globalJsonResp.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        var globalJsonText = await globalJsonResp.Content.ReadAsStringAsync();
        using (var doc = JsonDocument.Parse(globalJsonText))
        {
            doc.RootElement.TryGetProperty("alerts", out _).Should().BeTrue();
            doc.RootElement.TryGetProperty("integrity", out _).Should().BeTrue();
            doc.RootElement.TryGetProperty("mitreTechniques", out _).Should().BeTrue();
        }

        // 3. Rapport mono-alerte PDF
        var alertPdfResp = await client.GetAsync($"{ApiRoutes.Fill(ApiRoutes.ReportAlert, alertId)}?format=pdf");
        alertPdfResp.StatusCode.Should().Be(HttpStatusCode.OK);
        alertPdfResp.Content.Headers.ContentType!.MediaType.Should().Be("application/pdf");
        var alertPdfBytes = await alertPdfResp.Content.ReadAsByteArrayAsync();
        Encoding.ASCII.GetString(alertPdfBytes, 0, 5).Should().Be("%PDF-");

        // 4. Rapport mono-alerte JSON
        var alertJsonResp = await client.GetAsync($"{ApiRoutes.Fill(ApiRoutes.ReportAlert, alertId)}?format=json");
        alertJsonResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var alertJsonText = await alertJsonResp.Content.ReadAsStringAsync();
        using (var doc = JsonDocument.Parse(alertJsonText))
        {
            doc.RootElement.TryGetProperty("detail", out _).Should().BeTrue();
            doc.RootElement.TryGetProperty("mitreTechniques", out _).Should().BeTrue();
        }

        // 5. Métriques d'évaluation (POST + GET)
        var metrics = new[]
        {
            new ScenarioMetricDto("Phishing", "A-RulesOnly", true, 4, 18.5, 82, 0),
            new ScenarioMetricDto("Phishing", "C-FullCorrelation", true, 2, 4.1, 95, 0)
        };
        var postEval = await client.PostAsJsonAsync(ApiRoutes.Evaluation, metrics, SentinelJson.Options);
        postEval.StatusCode.Should().Be(HttpStatusCode.OK);

        var loadedEval = await client.GetFromJsonAsync<ScenarioMetricDto[]>(ApiRoutes.Evaluation, SentinelJson.Options);
        loadedEval.Should().HaveCount(2);
        loadedEval!.Should().Contain(m => m.Configuration == "C-FullCorrelation" && m.EventsBeforeAlert == 2);
    }

    [Fact]
    public async Task Cryptographic_Integrity_Detects_Direct_Sqlite_Tampering_On_Audit_Chain()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();
        await ActivateDeterministicModeAsync(client);

        var ingestion = factory.Services.GetRequiredService<EventIngestionService>();
        await ingestion.IngestBatchAsync(BuildPhishingChainEvents("WS-INT-01", "frank"));

        // Génère une entrée d'audit supplémentaire
        await client.GetAsync(ApiRoutes.Fill(ApiRoutes.EntityProfile, EntityKind.Host, "WS-INT-01"));

        // 1. Avant altération : les deux chaînes sont intègres
        var beforeReports = await client.GetFromJsonAsync<IntegrityReportDto[]>(ApiRoutes.AuditVerify, SentinelJson.Options);
        beforeReports.Should().NotBeNull();
        beforeReports!.Should().HaveCount(2);
        beforeReports.Should().OnlyContain(r => r.Valid && r.FirstBrokenId == null && r.CheckedEntries > 0);

        // 2. Falsification directe dans SQLite sur une ligne d'audit
        long tamperedId;
        var dbFactory = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
        await using (var db = await dbFactory.CreateDbContextAsync())
        {
            var target = await db.AuditEntries.AsNoTracking().OrderBy(a => a.Id).Skip(1).FirstAsync();
            tamperedId = target.Id;
            await db.Database.ExecuteSqlRawAsync(
                "UPDATE AuditEntries SET Details = 'FALSIFICATION_DIRECTE_SQLITE' WHERE Id = {0}",
                tamperedId);
        }

        // 3. Vérification détecte immédiatement la rupture à l'ID exact
        var afterReports = await client.GetFromJsonAsync<IntegrityReportDto[]>(ApiRoutes.AuditVerify, SentinelJson.Options);
        var auditReport = afterReports!.Single(r => r.Scope == "audit");
        var eventsReport = afterReports!.Single(r => r.Scope == "events");

        auditReport.Valid.Should().BeFalse();
        auditReport.FirstBrokenId.Should().Be(tamperedId);
        eventsReport.Valid.Should().BeTrue();
    }

    [Fact]
    public async Task Settings_Put_Validates_Persists_And_Updates_Pipeline_Live()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();

        // 1. Rejette les seuils non croissants
        var invalid = await client.GetFromJsonAsync<SentinelSettings>(ApiRoutes.Settings, SentinelJson.Options);
        invalid!.Thresholds.Low = 60;
        invalid.Thresholds.Moderate = 50;
        var badResp = await client.PutAsJsonAsync(ApiRoutes.Settings, invalid, SentinelJson.Options);
        badResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // 2. Accepte, persiste et applique à IThreatPipeline
        var updated = new SentinelSettings
        {
            Mode = OperatingMode.Active,
            Thresholds = new ThreatThresholds { Low = 25, Moderate = 50, High = 72, Critical = 88 },
            EventRetentionDays = 60,
            AlertRetentionDays = 180,
            ExcludedDomains = ["microsoft.com", "intranet.corp"],
            Llm = new LlmSettings { Enabled = false, Model = "qwen2.5:3b", TimeoutSeconds = 8 }
        };

        var putResp = await client.PutAsJsonAsync(ApiRoutes.Settings, updated, SentinelJson.Options);
        putResp.StatusCode.Should().Be(HttpStatusCode.OK);

        var reloaded = await client.GetFromJsonAsync<SentinelSettings>(ApiRoutes.Settings, SentinelJson.Options);
        reloaded!.Mode.Should().Be(OperatingMode.Active);
        reloaded.Thresholds.High.Should().Be(72);
        reloaded.Thresholds.Critical.Should().Be(88);
        reloaded.ExcludedDomains.Should().Contain("intranet.corp");

        var pipeline = factory.Services.GetRequiredService<IThreatPipeline>();
        pipeline.Settings.Mode.Should().Be(OperatingMode.Active);
        pipeline.Settings.Thresholds.High.Should().Be(72);
        pipeline.Settings.Thresholds.Critical.Should().Be(88);
        pipeline.Settings.Llm.Enabled.Should().BeFalse();
    }

    private static async Task ActivateDeterministicModeAsync(HttpClient client)
    {
        var settings = await client.GetFromJsonAsync<SentinelSettings>(ApiRoutes.Settings, SentinelJson.Options);
        settings!.Mode = OperatingMode.Active;
        settings.Llm.Enabled = false;
        var resp = await client.PutAsJsonAsync(ApiRoutes.Settings, settings, SentinelJson.Options);
        resp.EnsureSuccessStatusCode();
    }

    private static List<SecurityEvent> BuildPhishingChainEvents(string hostId, string userId)
    {
        var t0 = DateTimeOffset.UtcNow.AddMinutes(-2);
        const string domain = "evil-phish.xyz";
        const string sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var filePath = $@"C:\Users\{userId}\Downloads\facture.pdf.exe";

        return
        [
            SecurityEvent.Create(
                hostId, userId, EventCategory.Clipboard, EventTypes.ClipboardUrl,
                $"https://bit.ly/facture-2026",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = $"https://{domain}/facture",
                    [AttributeKeys.Domain] = domain,
                    [AttributeKeys.IsShortener] = "true",
                    [AttributeKeys.ContentType] = "url",
                    [AttributeKeys.ContentHash] = sha256
                },
                correlationHints: domain,
                timestamp: t0),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.LinkClicked,
                $"https://{domain}/facture",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = $"https://{domain}/facture",
                    [AttributeKeys.Domain] = domain,
                    [AttributeKeys.IsShortener] = "true",
                    [AttributeKeys.DomainAgeDays] = "2",
                    [AttributeKeys.Browser] = "msedge",
                    [AttributeKeys.TabId] = "tab-42"
                },
                correlationHints: domain,
                timestamp: t0.AddSeconds(8)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileCreated,
                filePath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = filePath,
                    [AttributeKeys.FileName] = "facture.pdf.exe",
                    [AttributeKeys.Extension] = ".exe",
                    [AttributeKeys.DoubleExtension] = "true",
                    [AttributeKeys.IsExecutable] = "true",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Downloads,
                    [AttributeKeys.Domain] = domain,
                    [AttributeKeys.Sha256] = sha256
                },
                correlationHints: $"{domain},{sha256}",
                timestamp: t0.AddSeconds(20)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart,
                filePath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "4812",
                    [AttributeKeys.ProcessName] = "facture.pdf.exe",
                    [AttributeKeys.ProcessPath] = filePath,
                    [AttributeKeys.ParentProcessId] = "1204",
                    [AttributeKeys.ParentProcessName] = "msedge.exe",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.Sha256] = sha256
                },
                correlationHints: sha256,
                timestamp: t0.AddSeconds(32)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.NetworkConnection,
                domain,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Domain] = domain,
                    [AttributeKeys.RemoteIp] = "185.220.101.42",
                    [AttributeKeys.RemotePort] = "443",
                    [AttributeKeys.IsPrivateIp] = "false",
                    [AttributeKeys.ProcessId] = "4812",
                    [AttributeKeys.ProcessName] = "facture.pdf.exe"
                },
                correlationHints: domain,
                timestamp: t0.AddSeconds(45))
        ];
    }
}
