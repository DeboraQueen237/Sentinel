using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Admin.Services;

public sealed record DownloadedFile(byte[] Content, string FileName, string ContentType);

public sealed class SentinelApiException : Exception
{
    public HttpStatusCode? StatusCode { get; }
    public string ErrorCode { get; }
    public bool IsUnauthorized => StatusCode == HttpStatusCode.Unauthorized;
    public bool IsConnectionFailure => StatusCode is null;

    public SentinelApiException(string message, HttpStatusCode? statusCode = null, string errorCode = "API_ERROR", Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Client HTTP typé consommant l'intégralité du contrat REST <see cref="ApiRoutes"/> exposé par Sentinel.Server.
/// </summary>
public sealed class SentinelApiClient
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly AdminSessionState _session;
    private readonly ILogger<SentinelApiClient> _logger;

    public SentinelApiClient(
        IHttpClientFactory httpFactory,
        AdminSessionState session,
        ILogger<SentinelApiClient> logger)
    {
        _httpFactory = httpFactory;
        _session = session;
        _logger = logger;
    }

    // ------------------------------------------------------------------------- Auth
    public Task<AuthStatusDto> GetAuthStatusAsync(CancellationToken ct = default) =>
        SendAsync<AuthStatusDto>(HttpMethod.Get, ApiRoutes.AuthStatus, null, requireAuth: false, ct);

    public Task<SetupResponse> SetupAsync(SetupRequest request, CancellationToken ct = default) =>
        SendAsync<SetupResponse>(HttpMethod.Post, ApiRoutes.AuthSetup, request, requireAuth: false, ct);

    public Task<LoginResponse> LoginAsync(LoginRequest request, CancellationToken ct = default) =>
        SendAsync<LoginResponse>(HttpMethod.Post, ApiRoutes.AuthLogin, request, requireAuth: false, ct);

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        try
        {
            await SendNoContentAsync(HttpMethod.Post, ApiRoutes.AuthLogout, null, requireAuth: true, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur ignorée lors de la déconnexion distante.");
        }
        finally
        {
            await _session.ClearAsync();
        }
    }

    public Task ChangePasswordAsync(ChangePasswordRequest request, CancellationToken ct = default) =>
        SendNoContentAsync(HttpMethod.Post, ApiRoutes.AuthChangePassword, request, requireAuth: true, ct);

    // ------------------------------------------------------------------------- Tableau de bord
    public Task<DashboardSummaryDto> GetDashboardSummaryAsync(CancellationToken ct = default) =>
        SendAsync<DashboardSummaryDto>(HttpMethod.Get, ApiRoutes.DashboardSummary, null, true, ct);

    public Task<IReadOnlyList<TimeSeriesPointDto>> GetTimelineAsync(string range = "24h", CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<TimeSeriesPointDto>>(
            HttpMethod.Get,
            BuildUrl(ApiRoutes.DashboardTimeline, ("range", range)),
            null, true, ct);

    // ------------------------------------------------------------------------- Alertes
    public Task<PagedResult<AlertDto>> GetAlertsAsync(
        AlertStatus? status = null,
        ThreatLevel? level = null,
        ThreatType? type = null,
        string? hostId = null,
        string? search = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int page = 1,
        int pageSize = 25,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Alerts,
            ("status", status?.ToString()),
            ("level", level?.ToString()),
            ("type", type?.ToString()),
            ("hostId", hostId),
            ("search", search),
            ("from", from?.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to?.ToString("O", CultureInfo.InvariantCulture)),
            ("page", page.ToString(CultureInfo.InvariantCulture)),
            ("pageSize", pageSize.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<PagedResult<AlertDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<AlertDetailDto> GetAlertDetailAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<AlertDetailDto>(HttpMethod.Get, ApiRoutes.Fill(ApiRoutes.AlertById, id), null, true, ct);

    public Task<AlertDto> ApproveAlertAsync(Guid id, string? comment = null, CancellationToken ct = default) =>
        SendAsync<AlertDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.AlertApprove, id), new AlertDecisionRequest(comment), true, ct);

    public Task<AlertDto> RejectAlertAsync(Guid id, string? comment = null, CancellationToken ct = default) =>
        SendAsync<AlertDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.AlertReject, id), new AlertDecisionRequest(comment), true, ct);

    public Task<AlertDto> AcknowledgeAlertAsync(Guid id, string? comment = null, CancellationToken ct = default) =>
        SendAsync<AlertDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.AlertAcknowledge, id), new AlertDecisionRequest(comment), true, ct);

    public Task<AlertDto> ResolveAlertAsync(Guid id, string? comment = null, CancellationToken ct = default) =>
        SendAsync<AlertDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.AlertResolve, id), new AlertDecisionRequest(comment), true, ct);

    public Task<AiIncidentAnalysisDto> AnalyzeAlertWithAiAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<AiIncidentAnalysisDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.AlertAiAnalyze, id), null, true, ct);

    public Task<PurgeDuplicatesResultDto> PurgeDuplicateAlertsAsync(CancellationToken ct = default) =>
        SendAsync<PurgeDuplicatesResultDto>(HttpMethod.Post, ApiRoutes.AlertsPurgeDuplicates, null, true, ct);

    // ------------------------------------------------------------------------- Événements
    public Task<PagedResult<EventDto>> GetEventsAsync(
        EventCategory? category = null,
        int? minScore = null,
        string? hostId = null,
        string? search = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Events,
            ("category", category?.ToString()),
            ("minScore", minScore?.ToString(CultureInfo.InvariantCulture)),
            ("hostId", hostId),
            ("search", search),
            ("from", from?.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to?.ToString("O", CultureInfo.InvariantCulture)),
            ("page", page.ToString(CultureInfo.InvariantCulture)),
            ("pageSize", pageSize.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<PagedResult<EventDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<EventDto> GetEventByIdAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<EventDto>(HttpMethod.Get, ApiRoutes.Fill(ApiRoutes.EventById, id), null, true, ct);

    // ------------------------------------------------------------------------- Clusters & Graphe
    public Task<PagedResult<ClusterDto>> GetClustersAsync(
        int? minScore = null,
        string? hostId = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int page = 1,
        int pageSize = 30,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Clusters,
            ("minScore", minScore?.ToString(CultureInfo.InvariantCulture)),
            ("hostId", hostId),
            ("from", from?.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to?.ToString("O", CultureInfo.InvariantCulture)),
            ("page", page.ToString(CultureInfo.InvariantCulture)),
            ("pageSize", pageSize.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<PagedResult<ClusterDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<ClusterDto> GetClusterByIdAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ClusterDto>(HttpMethod.Get, ApiRoutes.Fill(ApiRoutes.ClusterById, id), null, true, ct);

    public Task<AiIncidentAnalysisDto> AnalyzeClusterWithAiAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<AiIncidentAnalysisDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.ClusterAiAnalyze, id), null, true, ct);

    public Task<GraphDto> GetGraphAsync(
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        string? hostId = null,
        int? minScore = null,
        Guid? clusterId = null,
        int? limit = null,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Graph,
            ("from", from?.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to?.ToString("O", CultureInfo.InvariantCulture)),
            ("hostId", hostId),
            ("minScore", minScore?.ToString(CultureInfo.InvariantCulture)),
            ("clusterId", clusterId?.ToString()),
            ("limit", limit?.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<GraphDto>(HttpMethod.Get, url, null, true, ct);
    }

    // ------------------------------------------------------------------------- Actions & blocages
    public Task<PagedResult<ActionTicketDto>> GetActionsAsync(
        ActionStatus? status = null,
        ResponseActionType? type = null,
        string? hostId = null,
        bool? activeOnly = null,
        int page = 1,
        int pageSize = 25,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Actions,
            ("status", status?.ToString()),
            ("type", type?.ToString()),
            ("hostId", hostId),
            ("activeOnly", activeOnly.HasValue ? (activeOnly.Value ? "true" : "false") : null),
            ("page", page.ToString(CultureInfo.InvariantCulture)),
            ("pageSize", pageSize.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<PagedResult<ActionTicketDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<ActionTicketDto> CreateManualActionAsync(ManualActionRequest request, CancellationToken ct = default) =>
        SendAsync<ActionTicketDto>(HttpMethod.Post, ApiRoutes.Actions, request, true, ct);

    public Task<ActionTicketDto> ApproveActionAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ActionTicketDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.ActionApprove, id), null, true, ct);

    public Task<ActionTicketDto> RejectActionAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ActionTicketDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.ActionReject, id), null, true, ct);

    public Task<ActionTicketDto> RevertActionAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ActionTicketDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.ActionRevert, id), null, true, ct);

    // ------------------------------------------------------------------------- Postes & Entités
    public Task<IReadOnlyList<HostDto>> GetHostsAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<HostDto>>(HttpMethod.Get, ApiRoutes.Hosts, null, true, ct);

    public Task<IReadOnlyList<EntitySummaryDto>> GetEntitiesAsync(
        EntityKind? kind = null,
        string? search = null,
        int limit = 100,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Entities,
            ("kind", kind?.ToString()),
            ("search", search),
            ("limit", limit.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<IReadOnlyList<EntitySummaryDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<EntityProfileDto> GetEntityProfileAsync(EntityKind kind, string key, CancellationToken ct = default) =>
        SendAsync<EntityProfileDto>(HttpMethod.Get, ApiRoutes.Fill(ApiRoutes.EntityProfile, kind, key), null, true, ct);

    // ------------------------------------------------------------------------- Rapports & Évaluation
    public Task<DownloadedFile> DownloadReportAsync(
        DateTimeOffset from,
        DateTimeOffset to,
        ReportFormat format,
        string? hostId = null,
        CancellationToken ct = default)
    {
        var ext = format == ReportFormat.Pdf ? "pdf" : "json";
        var url = BuildUrl(ApiRoutes.ReportGenerate,
            ("from", from.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to.ToString("O", CultureInfo.InvariantCulture)),
            ("format", ext),
            ("hostId", hostId));
        var fallbackName = $"sentinel-rapport-{DateTime.Now:yyyyMMdd-HHmm}.{ext}";
        return DownloadBinaryAsync(url, fallbackName, format == ReportFormat.Pdf ? "application/pdf" : "application/json", ct);
    }

    public Task<DownloadedFile> DownloadAlertReportAsync(Guid id, ReportFormat format, CancellationToken ct = default)
    {
        var ext = format == ReportFormat.Pdf ? "pdf" : "json";
        var url = BuildUrl(ApiRoutes.Fill(ApiRoutes.ReportAlert, id), ("format", ext));
        var fallbackName = $"sentinel-alerte-{id.ToString()[..8]}.{ext}";
        return DownloadBinaryAsync(url, fallbackName, format == ReportFormat.Pdf ? "application/pdf" : "application/json", ct);
    }

    public Task<IReadOnlyList<ScenarioMetricDto>> GetEvaluationAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<ScenarioMetricDto>>(HttpMethod.Get, ApiRoutes.Evaluation, null, true, ct);

    // ------------------------------------------------------------------------- Paramètres
    public Task<SentinelSettings> GetSettingsAsync(CancellationToken ct = default) =>
        SendAsync<SentinelSettings>(HttpMethod.Get, ApiRoutes.Settings, null, true, ct);

    public Task<SentinelSettings> SaveSettingsAsync(SentinelSettings settings, CancellationToken ct = default) =>
        SendAsync<SentinelSettings>(HttpMethod.Put, ApiRoutes.Settings, settings, true, ct);

    // ------------------------------------------------------------------------- Audit & Intégrité
    public Task<PagedResult<AuditEntryDto>> GetAuditAsync(
        string? actor = null,
        string? action = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default)
    {
        var url = BuildUrl(ApiRoutes.Audit,
            ("actor", actor),
            ("action", action),
            ("from", from?.ToString("O", CultureInfo.InvariantCulture)),
            ("to", to?.ToString("O", CultureInfo.InvariantCulture)),
            ("page", page.ToString(CultureInfo.InvariantCulture)),
            ("pageSize", pageSize.ToString(CultureInfo.InvariantCulture)));
        return SendAsync<PagedResult<AuditEntryDto>>(HttpMethod.Get, url, null, true, ct);
    }

    public Task<IReadOnlyList<IntegrityReportDto>> VerifyIntegrityAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<IntegrityReportDto>>(HttpMethod.Get, ApiRoutes.AuditVerify, null, true, ct);

    // ------------------------------------------------------------------------- Système
    public Task<SystemHealthDto> GetHealthAsync(CancellationToken ct = default) =>
        SendAsync<SystemHealthDto>(HttpMethod.Get, ApiRoutes.Health, null, true, ct);

    public Task<IReadOnlyList<AgentHealthDto>> GetAgentsHealthAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<AgentHealthDto>>(HttpMethod.Get, ApiRoutes.AgentsHealth, null, true, ct);

    public Task<LlmStatusDto> GetLlmStatusAsync(CancellationToken ct = default) =>
        SendAsync<LlmStatusDto>(HttpMethod.Get, ApiRoutes.LlmStatus, null, true, ct);

    public Task<LlmStatusDto> AutoSelectLlmModelAsync(CancellationToken ct = default) =>
        SendAsync<LlmStatusDto>(HttpMethod.Post, ApiRoutes.LlmSelectBest, null, true, ct);

    // ------------------------------------------------------------------------- Scan général, Audit sécurité & Démo (v2.2)
    public Task<SystemScanReportDto> RunGeneralSystemScanAsync(bool ingestAnomalies = true, bool includeAiSummary = true, CancellationToken ct = default) =>
        SendAsync<SystemScanReportDto>(HttpMethod.Post, ApiRoutes.SystemScan, new SystemScanRequest(ingestAnomalies, includeAiSummary), true, ct);

    public async Task<SystemScanReportDto?> GetLastSystemScanAsync(CancellationToken ct = default)
    {
        try { return await SendAsync<SystemScanReportDto?>(HttpMethod.Get, ApiRoutes.SystemScanLast, null, true, ct); }
        catch { return null; }
    }

    public Task<SecurityAuditReportDto> RunSystemSecurityAuditAsync(CancellationToken ct = default) =>
        SendAsync<SecurityAuditReportDto>(HttpMethod.Post, ApiRoutes.SystemSecurityAudit, null, true, ct);

    public async Task<SecurityAuditReportDto?> GetLastSystemSecurityAuditAsync(CancellationToken ct = default)
    {
        try { return await SendAsync<SecurityAuditReportDto?>(HttpMethod.Get, ApiRoutes.SystemSecurityAuditLast, null, true, ct); }
        catch { return null; }
    }

    public Task<DemoScenarioResultDto> RunDemoScenarioAsync(string scenarioId, CancellationToken ct = default) =>
        SendAsync<DemoScenarioResultDto>(HttpMethod.Post, ApiRoutes.DemoRun, new DemoRunRequest(scenarioId), true, ct);

    // ------------------------------------------------------------------------- Notifications externes & In-App (v2.2)
    public Task<NotificationStatusDto> GetNotificationStatusAsync(CancellationToken ct = default) =>
        SendAsync<NotificationStatusDto>(HttpMethod.Get, ApiRoutes.NotificationStatus, null, true, ct);

    public Task<IReadOnlyList<InAppNotificationDto>> GetNotificationInboxAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<InAppNotificationDto>>(HttpMethod.Get, ApiRoutes.NotificationInbox, null, true, ct);

    public async Task MarkNotificationsReadAsync(CancellationToken ct = default) =>
        await SendNoContentAsync(HttpMethod.Post, ApiRoutes.NotificationInboxReadAll, null, true, ct);

    public Task<NotificationDeliveryDto> TestNotificationAsync(string channel, CancellationToken ct = default) =>
        SendAsync<NotificationDeliveryDto>(HttpMethod.Post, ApiRoutes.NotificationTest, new NotificationTestRequest(channel), true, ct);

    public Task<NotificationSecretsStatusDto> UpdateNotificationSecretsAsync(NotificationSecretsRequest request, CancellationToken ct = default) =>
        SendAsync<NotificationSecretsStatusDto>(HttpMethod.Put, ApiRoutes.NotificationSecrets, request, true, ct);

    // ------------------------------------------------------------------------- Détection v2 (Intel, Règles, Scan, ML, Canaris, Feedback)
    public Task<ThreatIntelStatusDto> GetThreatIntelStatusAsync(CancellationToken ct = default) =>
        SendAsync<ThreatIntelStatusDto>(HttpMethod.Get, ApiRoutes.ThreatIntelStatus, null, true, ct);

    public Task<ThreatIntelLookupDto> LookupThreatIntelAsync(string type, string value, CancellationToken ct = default) =>
        SendAsync<ThreatIntelLookupDto>(
            HttpMethod.Get,
            BuildUrl(ApiRoutes.ThreatIntelLookup, ("type", type), ("value", value)),
            null, true, ct);

    public Task<ThreatIntelStatusDto> RefreshThreatIntelAsync(CancellationToken ct = default) =>
        SendAsync<ThreatIntelStatusDto>(HttpMethod.Post, ApiRoutes.ThreatIntelRefresh, null, true, ct);

    public Task<IReadOnlyList<RuleSummaryDto>> GetRulesAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<RuleSummaryDto>>(HttpMethod.Get, ApiRoutes.Rules, null, true, ct);

    public Task<RuleSummaryDto> ToggleRuleAsync(string id, bool enabled, CancellationToken ct = default) =>
        SendAsync<RuleSummaryDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.RuleToggle, id), new RuleToggleRequest(enabled), true, ct);

    public Task<RulesReloadResultDto> ReloadRulesAsync(CancellationToken ct = default) =>
        SendAsync<RulesReloadResultDto>(HttpMethod.Post, ApiRoutes.RulesReload, null, true, ct);

    public Task<StaticScanResultDto> RunStaticScanAsync(string filePath, CancellationToken ct = default) =>
        SendAsync<StaticScanResultDto>(HttpMethod.Post, ApiRoutes.StaticScan, new StaticScanRequest(filePath), true, ct);

    public Task<MlModelStatusDto> GetMlStatusAsync(CancellationToken ct = default) =>
        SendAsync<MlModelStatusDto>(HttpMethod.Get, ApiRoutes.MlStatus, null, true, ct);

    public Task<IReadOnlyList<CanaryStatusDto>> GetCanariesAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<CanaryStatusDto>>(HttpMethod.Get, ApiRoutes.Canaries, null, true, ct);

    public Task<IReadOnlyList<CanaryStatusDto>> RedeployCanariesAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<CanaryStatusDto>>(HttpMethod.Post, ApiRoutes.CanariesRedeploy, null, true, ct);

    public Task<IReadOnlyList<FeedbackHistoryEntryDto>> GetFeedbackHistoryAsync(CancellationToken ct = default) =>
        SendAsync<IReadOnlyList<FeedbackHistoryEntryDto>>(HttpMethod.Get, ApiRoutes.FeedbackHistory, null, true, ct);

    public Task<FeedbackHistoryEntryDto> RevertFeedbackAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<FeedbackHistoryEntryDto>(HttpMethod.Post, ApiRoutes.Fill(ApiRoutes.FeedbackRevert, id), null, true, ct);

    public Task<ClusterNarrativeDto?> GetClusterNarrativeAsync(Guid clusterId, CancellationToken ct = default) =>
        SendAsync<ClusterNarrativeDto?>(HttpMethod.Get, $"/api/clusters/{clusterId}/narrative", null, true, ct);

    public async Task<bool> PingAsync(CancellationToken ct = default)
    {
        try
        {
            var client = _httpFactory.CreateClient("SentinelServer");
            using var resp = await client.GetAsync(ApiRoutes.Ping, ct);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    // ------------------------------------------------------------------------- Infrastructure HTTP
    private async Task<T> SendAsync<T>(HttpMethod method, string relativeUrl, object? body, bool requireAuth, CancellationToken ct)
    {
        using var resp = await ExecuteRequestAsync("SentinelServer", method, relativeUrl, body, requireAuth, ct);
        if (resp.Content.Headers.ContentLength == 0)
        {
            throw new SentinelApiException("Réponse vide inattendue du serveur SENTINEL.", resp.StatusCode, "EMPTY_RESPONSE");
        }

        try
        {
            var result = await resp.Content.ReadFromJsonAsync<T>(SentinelJson.Options, ct);
            return result ?? throw new SentinelApiException("Réponse JSON invalide du serveur SENTINEL.", resp.StatusCode, "INVALID_JSON");
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Erreur de désérialisation sur {Method} {Url}", method, relativeUrl);
            throw new SentinelApiException("Format de réponse inattendu reçu du serveur SENTINEL.", resp.StatusCode, "DESERIALIZATION_ERROR", ex);
        }
    }

    private async Task SendNoContentAsync(HttpMethod method, string relativeUrl, object? body, bool requireAuth, CancellationToken ct)
    {
        using var _ = await ExecuteRequestAsync("SentinelServer", method, relativeUrl, body, requireAuth, ct);
    }

    private async Task<DownloadedFile> DownloadBinaryAsync(string relativeUrl, string fallbackFileName, string fallbackContentType, CancellationToken ct)
    {
        using var resp = await ExecuteRequestAsync("SentinelReports", HttpMethod.Get, relativeUrl, null, true, ct);
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        var fileName = resp.Content.Headers.ContentDisposition?.FileNameStar
            ?? resp.Content.Headers.ContentDisposition?.FileName?.Trim('"')
            ?? fallbackFileName;
        var contentType = resp.Content.Headers.ContentType?.MediaType ?? fallbackContentType;
        return new DownloadedFile(bytes, fileName, contentType);
    }

    private async Task<HttpResponseMessage> ExecuteRequestAsync(
        string clientName,
        HttpMethod method,
        string relativeUrl,
        object? body,
        bool requireAuth,
        CancellationToken ct)
    {
        var client = _httpFactory.CreateClient(clientName);
        using var req = new HttpRequestMessage(method, relativeUrl.TrimStart('/'));

        if (requireAuth)
        {
            if (string.IsNullOrWhiteSpace(_session.Token))
            {
                throw new SentinelApiException("Session expirée. Veuillez vous reconnecter.", HttpStatusCode.Unauthorized, "UNAUTHORIZED");
            }
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _session.Token);
        }

        if (body is not null)
        {
            var json = SentinelJson.Serialize(body);
            req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        HttpResponseMessage resp;
        try
        {
            resp = await client.SendAsync(req, ct);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Serveur SENTINEL injoignable ({Method} {Url})", method, relativeUrl);
            throw new SentinelApiException(
                "Le serveur SENTINEL est actuellement indisponible. Vérifiez que le service Sentinel.Server est démarré.",
                null, "SERVER_UNREACHABLE", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new SentinelApiException(
                "Le serveur SENTINEL a mis trop de temps à répondre (délai expiré).",
                null, "TIMEOUT", ex);
        }

        if (resp.IsSuccessStatusCode)
        {
            return resp;
        }

        var statusCode = resp.StatusCode;
        var (code, message) = await TryReadErrorAsync(resp, ct);
        resp.Dispose();

        if (statusCode == HttpStatusCode.Unauthorized && requireAuth)
        {
            await _session.ClearAsync();
            throw new SentinelApiException(
                string.IsNullOrWhiteSpace(message) ? "Votre session a expiré. Veuillez vous reconnecter." : message,
                HttpStatusCode.Unauthorized, code);
        }

        throw new SentinelApiException(
            string.IsNullOrWhiteSpace(message) ? DefaultMessageFor(statusCode) : message,
            statusCode, code);
    }

    private static async Task<(string Code, string Message)> TryReadErrorAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    var err = JsonSerializer.Deserialize<ApiError>(text, SentinelJson.Options);
                    if (err is not null && !string.IsNullOrWhiteSpace(err.Message))
                    {
                        return (err.Code ?? "API_ERROR", err.Message);
                    }
                }
                catch
                {
                    // Peut être du texte brut ou ProblemDetails
                    if (text.Length < 240 && !text.TrimStart().StartsWith('<'))
                        return ("HTTP_ERROR", text.Trim());
                }
            }
        }
        catch
        {
            // Ignoré
        }
        return ($"HTTP_{(int)resp.StatusCode}", DefaultMessageFor(resp.StatusCode));
    }

    private static string DefaultMessageFor(HttpStatusCode code) => code switch
    {
        HttpStatusCode.BadRequest => "Requête invalide. Vérifiez les paramètres saisis.",
        HttpStatusCode.Unauthorized => "Identifiants invalides ou session expirée.",
        HttpStatusCode.Forbidden => "Accès refusé à cette ressource.",
        HttpStatusCode.NotFound => "Élément introuvable sur le serveur.",
        HttpStatusCode.Conflict => "Conflit d'état lors de l'opération demandée.",
        HttpStatusCode.TooManyRequests => "Trop de tentatives. Veuillez patienter avant de réessayer.",
        HttpStatusCode.ServiceUnavailable => "Le serveur SENTINEL est momentanément indisponible.",
        _ => $"Erreur serveur ({(int)code})."
    };

    private static string BuildUrl(string path, params (string Key, string? Value)[] query)
    {
        var parts = new List<string>(query.Length);
        foreach (var (key, value) in query)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}");
            }
        }
        return parts.Count == 0 ? path : $"{path}?{string.Join("&", parts)}";
    }
}
