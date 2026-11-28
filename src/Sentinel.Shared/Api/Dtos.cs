using Sentinel.Shared.Models;

namespace Sentinel.Shared.Api;

// ============================================================================================
//  Contrat REST Sentinel.Server  <->  Sentinel.Admin
//  Toutes les routes (sauf /api/auth/status, /api/auth/setup, /api/auth/login, /api/system/ping)
//  exigent l'en-tête  "Authorization: Bearer <token>"  obtenu via /api/auth/login.
//  JSON : System.Text.Json, camelCase, enums sérialisés en chaînes (JsonStringEnumConverter).
// ============================================================================================

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record ApiError(string Code, string Message);

// ----------------------------------------------------------------------------- Authentification
public sealed record AuthStatusDto(bool IsConfigured, string? Username);
public sealed record SetupRequest(string Username, string Password);
/// <summary>Secret TOTP (Base32) et URI otpauth:// pour le QR code. Le compte est activé dès le premier login TOTP réussi.</summary>
public sealed record SetupResponse(string TotpSecret, string OtpAuthUri);
public sealed record LoginRequest(string Username, string Password, string TotpCode);
public sealed record LoginResponse(string Token, DateTimeOffset ExpiresAt, string Username);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword, string TotpCode);

// ----------------------------------------------------------------------------- Événements
public sealed record EventDto(
    Guid Id,
    DateTimeOffset Timestamp,
    string HostId,
    string UserId,
    EventCategory Category,
    string EventType,
    string Subject,
    IReadOnlyDictionary<string, string> Attributes,
    int Score,
    ThreatLevel Level,
    ThreatType ThreatType,
    string Justification,
    AssessmentSource Source,
    double Confidence,
    IReadOnlyList<string> MatchedRules,
    IReadOnlyList<string> MitreTechniques,
    Guid? ClusterId);

// ----------------------------------------------------------------------------- Clusters
public sealed record ClusterDto(
    Guid Id,
    string HostId,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    int Score,
    int MaxEventScore,
    ThreatLevel Level,
    ThreatType DominantType,
    int EventCount,
    bool Escalated,
    string? ChainId,
    string? ChainName,
    int ChainStepsMatched,
    int ChainTotalSteps,
    IReadOnlyList<string> ContextKeys,
    IReadOnlyList<string> MitreTechniques,
    string Justification);

// ----------------------------------------------------------------------------- Alertes
public sealed record AlertDto(
    Guid Id,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    string HostId,
    string UserId,
    string Title,
    string Summary,
    int Score,
    ThreatLevel Level,
    ThreatType ThreatType,
    AlertStatus Status,
    Guid? ClusterId,
    int EventCount,
    int PendingActions,
    bool RequiresDecision,
    IReadOnlyList<string> MitreTechniques);

public sealed record AlertDetailDto(
    AlertDto Alert,
    string Justification,
    IReadOnlyList<EventDto> Events,
    ClusterDto? Cluster,
    IReadOnlyList<ActionTicketDto> Actions,
    IReadOnlyList<AlertHistoryEntryDto> History);

public sealed record AlertHistoryEntryDto(DateTimeOffset Timestamp, string Actor, string Action, string? Comment);

/// <summary>Corps des actions Approuver / Rejeter / Acquitter / Résoudre.</summary>
public sealed record AlertDecisionRequest(string? Comment);

// ----------------------------------------------------------------------------- Actions / blocages
public sealed record ActionTicketDto(
    Guid Id,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExecutedAt,
    DateTimeOffset? RevertedAt,
    string HostId,
    Guid? AlertId,
    ResponseActionType Type,
    string Target,
    ActionStatus Status,
    bool Automatic,
    bool Reversible,
    string Rationale,
    string? ResultMessage,
    IReadOnlyDictionary<string, string> Parameters);

/// <summary>Blocage manuel depuis l'écran « Actions &amp; blocages » (ex. bloquer un domaine).</summary>
public sealed record ManualActionRequest(string HostId, ResponseActionType Type, string Target, string? Comment);

// ----------------------------------------------------------------------------- Graphe
public sealed record GraphNodeDto(
    string Id,
    GraphNodeType Type,
    string Label,
    int Score,
    ThreatLevel Level,
    Guid? ClusterId,
    DateTimeOffset? Timestamp,
    IReadOnlyDictionary<string, string> Data);

public sealed record GraphEdgeDto(
    string Id,
    string Source,
    string Target,
    GraphEdgeType Type,
    double Weight,
    string? Label);

public sealed record GraphDto(
    IReadOnlyList<GraphNodeDto> Nodes,
    IReadOnlyList<GraphEdgeDto> Edges,
    IReadOnlyList<ClusterDto> Clusters);

// ----------------------------------------------------------------------------- Tableau de bord
/// <summary>Synthèse globale du tableau de bord (<c>GlobalSecurityScore</c> : 0..100, 100 = sain).</summary>
public sealed record DashboardSummaryDto(
    int GlobalSecurityScore,
    int ActiveAlerts,
    int CriticalAlerts,
    int AlertsAwaitingDecision,
    int ActiveBlocks,
    long EventsLast24h,
    int ClustersLast24h,
    int HostsOnline,
    int HostsTotal,
    OperatingMode Mode,
    bool LlmAvailable,
    string LlmModel,
    IReadOnlyDictionary<ThreatLevel, int> LevelDistribution24h,
    IReadOnlyDictionary<ThreatType, int> ThreatTypes24h,
    IReadOnlyDictionary<EventCategory, long> Categories24h,
    IReadOnlyList<AlertDto> RecentAlerts,
    DateTimeOffset GeneratedAt);

public sealed record TimeSeriesPointDto(
    DateTimeOffset Timestamp,
    long Events,
    int Alerts,
    int MaxScore,
    double AvgScore,
    int Blocks);

// ----------------------------------------------------------------------------- Postes et fiches
public sealed record HostDto(
    string HostId,
    string MachineName,
    string OsVersion,
    string AgentVersion,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    bool Online,
    int RiskScore,
    int OpenAlerts,
    IReadOnlyList<string> Users);

public enum EntityKind { Host, User, Domain, Process, File, Device, Ip }

public sealed record EntitySummaryDto(EntityKind Kind, string Key, string Label, int RiskScore, long EventCount, int AlertCount, DateTimeOffset LastSeen);

public sealed record EntityProfileDto(
    EntityKind Kind,
    string Key,
    string Label,
    int RiskScore,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    long EventCount,
    IReadOnlyList<AlertDto> Alerts,
    IReadOnlyList<EventDto> RecentEvents,
    IReadOnlyList<TimeSeriesPointDto> Activity,
    BaselineSummaryDto? Baseline,
    IReadOnlyDictionary<string, string> Properties);

/// <summary>Résumé de la baseline comportementale (doc §7.1-2).</summary>
public sealed record BaselineSummaryDto(
    IReadOnlyList<int> UsualHours,
    IReadOnlyList<string> FrequentProcesses,
    IReadOnlyList<string> FrequentDomains,
    double AvgEventsPerHour,
    double TypingKpsMean,
    DateTimeOffset UpdatedAt);

// ----------------------------------------------------------------------------- Audit
public sealed record AuditEntryDto(
    long Id,
    DateTimeOffset Timestamp,
    string Actor,
    string Action,
    string Target,
    string? Details,
    string? IpAddress,
    string Hash,
    string PreviousHash);

public sealed record IntegrityReportDto(bool Valid, long CheckedEntries, long? FirstBrokenId, string Scope);

// ----------------------------------------------------------------------------- Système
public sealed record SystemHealthDto(
    string Version,
    DateTimeOffset StartedAt,
    bool DatabaseOk,
    bool LlmAvailable,
    string LlmModel,
    double LlmAvgLatencyMs,
    long EventsProcessed,
    double AvgPipelineLatencyMs,
    double LlmUsageRatio,
    int AgentsConnected,
    OperatingMode Mode,
    long ProcessWorkingSetMb);

// ----------------------------------------------------------------------------- Rapports / évaluation
public enum ReportFormat { Pdf, Json }

public sealed record ReportRequest(DateTimeOffset From, DateTimeOffset To, ReportFormat Format, string? HostId);

/// <summary>Résultat d'évaluation d'un scénario (doc §8.4, §14) – Time-To-Detect.</summary>
public sealed record ScenarioMetricDto(
    string Scenario,
    string Configuration,
    bool Detected,
    int EventsBeforeAlert,
    double SecondsToDetect,
    int PeakScore,
    int FalsePositives);

// ----------------------------------------------------------------------------- Extensions v2 (M1–M11)
public sealed record CollectorHealthDto(string Name, bool Running, string? Error, long EventsProduced);

public sealed record AgentHealthDto(
    string HostId,
    string MachineName,
    string OsVersion,
    string AgentVersion,
    bool Online,
    DateTimeOffset LastSeen,
    double CpuPercent,
    long WorkingSetMb,
    int QueueLength,
    long EventsCollected,
    bool DefenderActive,
    bool DefenderRealtimeEnabled,
    bool SysmonInstalled,
    IReadOnlyList<CollectorHealthDto> Collectors);

public sealed record ThreatIntelFeedDto(
    string Name,
    string License,
    bool Enabled,
    bool Online,
    DateTimeOffset? LastUpdated,
    int IndicatorCount,
    string? LastError);

public sealed record ThreatIntelStatusDto(
    int TotalIndicators,
    int HashCount,
    int DomainCount,
    int UrlCount,
    int IpCount,
    DateTimeOffset? LastRefresh,
    bool OfflineMode,
    IReadOnlyList<ThreatIntelFeedDto> Feeds);

public sealed record ThreatIntelLookupDto(
    bool Found,
    string IndicatorType,
    string Indicator,
    string? Source,
    string? ThreatType,
    DateTimeOffset? FirstSeen,
    DateTimeOffset? ExpiresAt,
    int SuggestedScore,
    string Justification,
    double ElapsedMs);

public sealed record RuleSummaryDto(
    string Id,
    string Engine,
    string Title,
    string Level,
    bool Enabled,
    string SourceFile,
    IReadOnlyList<string> MitreTechniques,
    long MatchCount,
    string? Description);

public sealed record RuleToggleRequest(bool Enabled);

public sealed record RulesReloadResultDto(int SigmaCount, int YaraCount, IReadOnlyList<string> Errors, DateTimeOffset ReloadedAt);

public sealed record StaticScanRequest(string FilePath);

public sealed record StaticScanResultDto(
    string FilePath,
    string Sha256,
    long SizeBytes,
    bool IsPe,
    bool Signed,
    string? Publisher,
    double MaxEntropy,
    string? ProbablePacker,
    bool TimestampAnomaly,
    IReadOnlyList<string> SuspiciousImports,
    IReadOnlyList<string> YaraMatches,
    string YaraEngine,
    double? MlMaliciousProbability,
    IReadOnlyList<string> MlTopFeatures,
    int CombinedScore,
    double ElapsedMs,
    string? Error);

public sealed record MlModelStatusDto(
    bool Loaded,
    string Version,
    string Algorithm,
    DateTimeOffset? TrainedAt,
    double Auc,
    double RecallAt01Fpr,
    double F1Score,
    int FeatureCount,
    string DatasetNotice,
    string ModelPath);

public sealed record CanaryStatusDto(
    string Id,
    string HostId,
    string FilePath,
    string Folder,
    string ExpectedSha256,
    long SizeBytes,
    bool Intact,
    DateTimeOffset DeployedAt,
    DateTimeOffset? LastCheckedAt,
    string Status);

public sealed record FeedbackHistoryEntryDto(
    Guid Id,
    DateTimeOffset RecordedAt,
    string Actor,
    Guid? AlertId,
    Guid? ClusterId,
    bool IsFalsePositive,
    string? Comment,
    bool Reverted,
    DateTimeOffset? RevertedAt);

public sealed record ClusterNarrativeDto(
    Guid ClusterId,
    string Narrative,
    double ChainProbability,
    IReadOnlyList<string> MitreTactics,
    IReadOnlyList<ScoreContribution> Contributions);

// ----------------------------------------------------------------------------- Extensions v2.1 (IA Qwen optimisée & Notifications multi-canaux)
public sealed record OllamaModelInfoDto(
    string Name,
    long SizeBytes,
    string? Family,
    string? ParameterSize,
    string? QuantizationLevel,
    bool IsQwen,
    bool Selected);

public sealed record LlmStatusDto(
    bool Enabled,
    bool Available,
    string Endpoint,
    string ConfiguredModel,
    string ActiveModel,
    bool AutoSelectBestQwen,
    bool AutoSelected,
    string SelectionReason,
    double HostRamGb,
    long Calls,
    long Successes,
    long Failures,
    long CacheHits,
    double AvgLatencyMs,
    int ContextWindow,
    int MaxOutputTokens,
    string KeepAlive,
    bool WarmedUp,
    IReadOnlyList<OllamaModelInfoDto> InstalledModels);

public sealed record NotificationSecretsStatusDto(
    bool HasSmtpPassword,
    bool HasWhatsAppToken,
    bool HasWebhookSecret,
    string StorageMode,
    bool HasSmsToken = false);

public sealed record NotificationSecretsRequest(
    string? SmtpPassword = null,
    string? WhatsAppAccessToken = null,
    string? WebhookSecret = null,
    bool ClearSmtpPassword = false,
    bool ClearWhatsAppToken = false,
    bool ClearWebhookSecret = false,
    string? SmsApiToken = null,
    bool ClearSmsToken = false);

public sealed record NotificationTestRequest(string Channel);

public sealed record NotificationDeliveryDto(
    Guid Id,
    DateTimeOffset Timestamp,
    string Channel,
    string TriggerKind,
    ThreatLevel Level,
    string HostId,
    string Summary,
    bool Success,
    string? Error,
    int Attempts,
    double ElapsedMs);

public sealed record InAppNotificationDto(
    Guid Id,
    DateTimeOffset Timestamp,
    ThreatLevel Level,
    int Score,
    string TriggerKind,
    string Title,
    string Message,
    string HostId,
    string? TargetUrl,
    bool IsRead);

public sealed record NotificationStatusDto(
    bool GlobalEnabled,
    bool EmailEnabled,
    ThreatLevel EmailMinLevel,
    bool WhatsAppEnabled,
    ThreatLevel WhatsAppMinLevel,
    string WhatsAppProvider,
    bool WebhookEnabled,
    ThreatLevel WebhookMinLevel,
    string WebhookFormat,
    int CooldownMinutes,
    bool NotifyOnCorrelatedCluster,
    int QueuedCount,
    long TotalSent,
    long TotalFailed,
    long SuppressedByCooldown,
    NotificationSecretsStatusDto Secrets,
    IReadOnlyList<NotificationDeliveryDto> RecentDeliveries,
    bool InAppEnabled = true,
    ThreatLevel InAppMinLevel = ThreatLevel.Moderate,
    int UnreadInAppCount = 0,
    bool SmsEnabled = false,
    ThreatLevel SmsMinLevel = ThreatLevel.Critical,
    string SmsProvider = "TwilioSms");

// ----------------------------------------------------------------------------- Extensions v2.2 (Diagnostic IA SOC, Scan système général, Audit sécurité & Démo)
public sealed record AiIncidentAnalysisDto(
    string TargetId,
    DateTimeOffset GeneratedAt,
    bool AiUsed,
    string ModelUsed,
    string ExecutiveSummary,
    string RootCauseHypothesis,
    IReadOnlyList<string> ImmediateActions,
    IReadOnlyList<string> HardeningSteps,
    double Confidence,
    double LatencyMs);

public sealed record SystemScanRequest(bool IngestAnomalies = true, bool IncludeAiSummary = true);

public sealed record SystemScanFindingDto(
    string Area,
    ThreatLevel Severity,
    int Score,
    string Title,
    string Subject,
    string Details,
    string Recommendation,
    IReadOnlyList<string> MitreTechniques,
    bool IngestedAsEvent);

public sealed record SystemScanReportDto(
    Guid ScanId,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    double DurationMs,
    string HostName,
    int ProcessesInspected,
    int ConnectionsInspected,
    int PersistenceEntriesInspected,
    int FilesScanned,
    int CanariesChecked,
    int AnomaliesFound,
    int EventsIngested,
    string? AiExecutiveSummary,
    IReadOnlyList<SystemScanFindingDto> Findings);

public sealed record SecurityAuditCheckDto(
    string Id,
    string Category,
    string Title,
    string Status,
    int Weight,
    string CurrentState,
    string Recommendation);

public sealed record SecurityAuditReportDto(
    Guid AuditId,
    DateTimeOffset GeneratedAt,
    double DurationMs,
    string HostName,
    int PostureScore,
    int PassedCount,
    int WarningCount,
    int CriticalCount,
    bool HashChainValid,
    string? AiActionPlan,
    IReadOnlyList<SecurityAuditCheckDto> Checks);

public sealed record DemoRunRequest(string ScenarioId);

public sealed record DemoScenarioResultDto(
    string ScenarioId,
    string Title,
    int EventsInjected,
    int AlertsGenerated,
    Guid? PrimaryClusterId,
    Guid? PrimaryAlertId,
    string Summary,
    double ElapsedMs);

public sealed record PurgeDuplicatesResultDto(int AlertsResolved, int RemainingOpenAlerts);
