namespace Sentinel.Shared.Api;

/// <summary>Routes REST exposées par Sentinel.Server (cf. Dtos.cs pour les corps).</summary>
public static class ApiRoutes
{
    public const string Base = "/api";

    // Auth (anonymes : Status, Setup, Login)
    public const string AuthStatus = "/api/auth/status";              // GET  -> AuthStatusDto
    public const string AuthSetup = "/api/auth/setup";                // POST SetupRequest -> SetupResponse (seulement si non configuré)
    public const string AuthLogin = "/api/auth/login";                // POST LoginRequest -> LoginResponse
    public const string AuthLogout = "/api/auth/logout";              // POST
    public const string AuthChangePassword = "/api/auth/password";    // POST ChangePasswordRequest

    // Tableau de bord
    public const string DashboardSummary = "/api/dashboard/summary";  // GET -> DashboardSummaryDto
    public const string DashboardTimeline = "/api/dashboard/timeline"; // GET ?range=24h|7d|30d -> TimeSeriesPointDto[]

    // Alertes
    public const string Alerts = "/api/alerts";                       // GET ?status&level&type&hostId&search&from&to&page&pageSize -> PagedResult<AlertDto>
    public const string AlertById = "/api/alerts/{id:guid}";          // GET -> AlertDetailDto
    public const string AlertApprove = "/api/alerts/{id:guid}/approve";     // POST AlertDecisionRequest -> AlertDto
    public const string AlertReject = "/api/alerts/{id:guid}/reject";       // POST (faux positif)  -> AlertDto
    public const string AlertAcknowledge = "/api/alerts/{id:guid}/acknowledge"; // POST -> AlertDto
    public const string AlertResolve = "/api/alerts/{id:guid}/resolve";     // POST -> AlertDto

    // Événements
    public const string Events = "/api/events";                       // GET ?category&minScore&hostId&search&from&to&page&pageSize -> PagedResult<EventDto>
    public const string EventById = "/api/events/{id:guid}";          // GET -> EventDto

    // Clusters / graphe
    public const string Clusters = "/api/clusters";                   // GET ?minScore&hostId&from&to&page&pageSize -> PagedResult<ClusterDto>
    public const string ClusterById = "/api/clusters/{id:guid}";      // GET -> ClusterDto
    public const string Graph = "/api/graph";                         // GET ?from&to&hostId&minScore&clusterId&limit -> GraphDto

    // Actions & blocages
    public const string Actions = "/api/actions";                     // GET ?status&type&hostId&activeOnly&page&pageSize -> PagedResult<ActionTicketDto> ; POST ManualActionRequest -> ActionTicketDto
    public const string ActionApprove = "/api/actions/{id:guid}/approve"; // POST -> ActionTicketDto
    public const string ActionReject = "/api/actions/{id:guid}/reject";   // POST -> ActionTicketDto
    public const string ActionRevert = "/api/actions/{id:guid}/revert";   // POST -> ActionTicketDto  (F7 : annulation en un clic)

    // Postes & fiches
    public const string Hosts = "/api/hosts";                         // GET -> HostDto[]
    public const string Entities = "/api/entities";                   // GET ?kind&search&limit -> EntitySummaryDto[]
    public const string EntityProfile = "/api/entities/{kind}/{key}"; // GET -> EntityProfileDto (consultation journalisée dans l'audit)

    // Rapports
    public const string ReportGenerate = "/api/reports";              // GET ?from&to&format=pdf|json&hostId -> fichier
    public const string ReportAlert = "/api/reports/alerts/{id:guid}"; // GET ?format=pdf|json -> fichier
    public const string Evaluation = "/api/reports/evaluation";       // GET -> ScenarioMetricDto[] (derniers résultats de simulation)

    // Paramètres
    public const string Settings = "/api/settings";                   // GET -> SentinelSettings ; PUT SentinelSettings

    // Audit
    public const string Audit = "/api/audit";                         // GET ?actor&action&from&to&page&pageSize -> PagedResult<AuditEntryDto>
    public const string AuditVerify = "/api/audit/verify";            // GET -> IntegrityReportDto[] (audit + journal d'événements)

    // Système
    public const string Health = "/api/system/health";                // GET -> SystemHealthDto
    public const string Ping = "/api/system/ping";                    // GET (anonyme) -> "pong"
    public const string AgentsHealth = "/api/system/agents";          // GET -> AgentHealthDto[]
    public const string LlmStatus = "/api/system/llm";                // GET -> LlmStatusDto
    public const string LlmSelectBest = "/api/system/llm/autoselect"; // POST -> LlmStatusDto

    // Notifications externes administrateur (v2.1 — Email, WhatsApp, Webhook/Slack/Teams/Telegram)
    public const string NotificationStatus = "/api/notifications/status";   // GET -> NotificationStatusDto
    public const string NotificationTest = "/api/notifications/test";       // POST NotificationTestRequest -> NotificationDeliveryDto
    public const string NotificationSecrets = "/api/notifications/secrets"; // PUT NotificationSecretsRequest -> NotificationSecretsStatusDto

    // Threat Intelligence (v2 M4)
    public const string ThreatIntelStatus = "/api/intel/status";      // GET -> ThreatIntelStatusDto
    public const string ThreatIntelLookup = "/api/intel/lookup";      // GET ?type=hash|domain|url|ip&value=... -> ThreatIntelLookupDto
    public const string ThreatIntelRefresh = "/api/intel/refresh";    // POST -> ThreatIntelStatusDto

    // Règles Sigma & YARA (v2 M2, M3)
    public const string Rules = "/api/rules";                         // GET -> RuleSummaryDto[]
    public const string RuleToggle = "/api/rules/{id}/toggle";        // POST RuleToggleRequest -> RuleSummaryDto
    public const string RulesReload = "/api/rules/reload";            // POST -> RulesReloadResultDto

    // Analyse statique à la demande (v2 M3)
    public const string StaticScan = "/api/static/scan";              // POST StaticScanRequest -> StaticScanResultDto

    // Modèle ML PE (v2 M5)
    public const string MlStatus = "/api/ml/status";                  // GET -> MlModelStatusDto

    // Fichiers canari (v2 M6)
    public const string Canaries = "/api/canaries";                   // GET -> CanaryStatusDto[]
    public const string CanariesRedeploy = "/api/canaries/redeploy";  // POST -> CanaryStatusDto[]

    // Retours analyste / corrélation (v2 M8)
    public const string FeedbackHistory = "/api/feedback";            // GET -> FeedbackHistoryEntryDto[]
    public const string FeedbackRevert = "/api/feedback/{id:guid}/revert"; // POST -> FeedbackHistoryEntryDto

    /// <summary>Remplace les paramètres de route : <c>ApiRoutes.Fill(ApiRoutes.AlertById, id)</c>.</summary>
    public static string Fill(string route, params object[] values)
    {
        var result = route;
        foreach (var v in values)
        {
            var start = result.IndexOf('{');
            if (start < 0) break;
            var end = result.IndexOf('}', start);
            result = string.Concat(result.AsSpan(0, start), Uri.EscapeDataString(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? ""), result.AsSpan(end + 1));
        }
        return result;
    }
}

/// <summary>
/// Hub SignalR temps réel exposé par Sentinel.Server sur <see cref="Path"/>.
/// Authentification : jeton Bearer passé via <c>?access_token=</c>.
/// </summary>
public static class LiveHub
{
    public const string Path = "/hubs/live";

    // Méthodes serveur -> client
    public const string EventScored = "EventScored";           // EventDto        (événements score >= 30 uniquement, pour limiter le débit)
    public const string AlertRaised = "AlertRaised";           // AlertDto
    public const string AlertUpdated = "AlertUpdated";         // AlertDto
    public const string ClusterUpdated = "ClusterUpdated";     // ClusterDto
    public const string ActionUpdated = "ActionUpdated";       // ActionTicketDto
    public const string HostStatusChanged = "HostStatusChanged"; // HostDto
    public const string SummaryChanged = "SummaryChanged";     // DashboardSummaryDto (au plus 1 / 2 s)
    public const string SettingsChanged = "SettingsChanged";   // SentinelSettings
}
