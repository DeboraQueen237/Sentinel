using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Core.Baseline;
using Sentinel.Core.Correlation;
using Sentinel.Core.Decision;
using Sentinel.Core.Enrichment;
using Sentinel.Core.Scoring;
using Sentinel.Detection.Sigma;
using Sentinel.ML;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;
using Sentinel.ThreatIntel;

namespace Sentinel.Core;

/// <summary>
/// Implémentation complète et thread-safe de <see cref="IThreatPipeline"/> :
/// pré-filtre/enrichissement → baseline → règles → scoring hybride (LLM) → corrélation → décision.
/// </summary>
public sealed class ThreatPipeline : IThreatPipeline
{
    private const int MaxRecentContextPerHost = 120;
    private const int MaxRecentHosts = 500;
    private const int MaxEventHistoryCache = 10_000;

    private readonly LocalReputationStore _reputation;
    private readonly EventPreFilter _preFilter;
    private readonly RuleEngine _ruleEngine;
    private readonly BehavioralBaseline _baseline;
    private readonly HybridScorer _hybridScorer;
    private readonly CorrelationEngine _correlation;
    private readonly DecisionEngine _decision;
    private readonly ILlmAssessor _llm;
    private readonly TimeProvider _clock;
    private readonly ILogger<ThreatPipeline> _logger;

    private readonly object _contextGate = new();
    private readonly Dictionary<string, LinkedList<RecentEventSummary>> _recentByHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, SecurityEvent> _eventLookup = new();
    private readonly Queue<Guid> _eventLookupOrder = new();
    private readonly List<FeedbackHistoryEntryDto> _feedbackHistory = new();

    private volatile SentinelSettings _settings;
    private long _eventsProcessed;
    private long _totalPipelineLatencyMicros;

    public ThreatPipeline(
        SentinelSettings initialSettings,
        ILlmAssessor llm,
        ILoggerFactory? loggerFactory = null,
        TimeProvider? clock = null,
        ISigmaEngine? sigma = null,
        IReputationService? threatIntel = null,
        IPeMlClassifier? mlClassifier = null)
    {
        ArgumentNullException.ThrowIfNull(initialSettings);
        ArgumentNullException.ThrowIfNull(llm);

        var lf = loggerFactory ?? NullLoggerFactory.Instance;
        _logger = lf.CreateLogger<ThreatPipeline>();
        _clock = clock ?? TimeProvider.System;
        _llm = llm;

        _settings = CloneSettings(initialSettings);
        _llm.UpdateSettings(_settings.Llm);

        _reputation = new LocalReputationStore();
        _preFilter = new EventPreFilter(_reputation);
        _ruleEngine = new RuleEngine();
        _baseline = new BehavioralBaseline();
        _hybridScorer = new HybridScorer(_preFilter, _ruleEngine, _baseline, _llm, lf.CreateLogger<HybridScorer>(), sigma, threatIntel, mlClassifier);
        _correlation = new CorrelationEngine();
        _decision = new DecisionEngine();
    }

    /// <inheritdoc />
    public SentinelSettings Settings => CloneSettings(_settings);

    /// <inheritdoc />
    public PipelineStats Stats
    {
        get
        {
            var processed = Interlocked.Read(ref _eventsProcessed);
            var totalMicros = Interlocked.Read(ref _totalPipelineLatencyMicros);
            var avgPipeMs = processed > 0 ? (totalMicros / 1000.0) / processed : 0.0;
            var llmMetrics = _llm.Metrics;

            return new PipelineStats(
                processed,
                llmMetrics.Calls,
                llmMetrics.Failures,
                Math.Round(avgPipeMs, 3),
                llmMetrics.AvgLatencyMs,
                _llm.IsAvailable,
                _correlation.ActiveClusterCount);
        }
    }

    /// <inheritdoc />
    public async ValueTask<PipelineResult> ProcessAsync(SecurityEvent evt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);
        var startTs = Stopwatch.GetTimestamp();
        var settings = _settings;

        // 1. Récupérer le contexte récent (30 min) uniquement si le LLM ou une promotion contextuelle en a besoin
        var needsContext = (settings.Llm.Enabled && _llm.IsAvailable)
                           || (evt.Category == EventCategory.Session && evt.EventType == EventTypes.LogonSuccess)
                           || (evt.Category == EventCategory.Process && evt.EventType == EventTypes.ProcessStart);
        var recentContext = needsContext ? GetRecentContext(evt.HostId, evt.Timestamp) : Array.Empty<RecentEventSummary>();

        // 2. Pré-filtre + baseline + règles + LLM hybride
        var scoring = await _hybridScorer.ScoreAsync(evt, settings, recentContext, ct).ConfigureAwait(false);
        var assessment = scoring.Assessment;

        // Enrichissement contextuel spécifique aux séquences critiques (ex. connexion réussie après échecs récents)
        assessment = ApplyContextualPromotion(evt, scoring.Enriched, assessment, recentContext);

        // 3. Mémoriser l'événement pour le contexte LLM et le retour analyste (ApplyFeedback)
        RememberEvent(evt, assessment);

        // 4. Corrélation par fenêtres glissantes (si activée)
        CorrelationCluster? cluster = null;
        IReadOnlyList<SecurityEvent>? clusterEvents = null;
        if (settings.Correlation.Enabled)
        {
            var corr = _correlation.Correlate(scoring.Enriched, assessment, settings);
            if (corr is not null)
            {
                cluster = corr.Cluster;
                clusterEvents = corr.ClusterEvents;
            }
        }

        // 5. Décision déterministe (matrice §9.2)
        var decision = _decision.Decide(evt, assessment, cluster, clusterEvents, settings, _clock.GetUtcNow());

        var elapsedMs = Stopwatch.GetElapsedTime(startTs).TotalMilliseconds;
        Interlocked.Increment(ref _eventsProcessed);
        Interlocked.Add(ref _totalPipelineLatencyMicros, (long)Math.Max(0, Math.Round(elapsedMs * 1000.0)));

        return new PipelineResult
        {
            Scored = new ScoredEvent(evt, assessment),
            Cluster = cluster,
            Decision = decision,
            ElapsedMs = Math.Round(elapsedMs, 3),
            LlmUsed = scoring.LlmUsed
        };
    }

    /// <inheritdoc />
    public void UpdateSettings(SentinelSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var copy = CloneSettings(settings);
        _settings = copy;
        _llm.UpdateSettings(copy.Llm);
        _logger.LogInformation("Paramètres SENTINEL mis à jour (mode={Mode}, corrélation={Corr}, LLM={Llm}).",
            copy.Mode, copy.Correlation.Enabled, copy.Llm.Enabled);
    }

    /// <inheritdoc />
    public void ApplyFeedback(AnalystFeedback feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);

        var resolvedEvents = new List<SecurityEvent>();
        var seen = new HashSet<Guid>();

        if (feedback.ClusterId is { } cid)
        {
            foreach (var e in _correlation.GetClusterEvents(cid))
            {
                if (seen.Add(e.Id)) resolvedEvents.Add(e);
            }
        }

        lock (_contextGate)
        {
            foreach (var eid in feedback.EventIds)
            {
                if (seen.Add(eid) && _eventLookup.TryGetValue(eid, out var evt))
                {
                    resolvedEvents.Add(evt);
                }
            }
        }

        foreach (var evt in resolvedEvents)
        {
            var processName = evt.Attr(AttributeKeys.ProcessName) ?? evt.Attr(AttributeKeys.ProcessPath);
            var domain = evt.Attr(AttributeKeys.Domain)
                         ?? ThreatIndicators.ExtractDomain(evt.Attr(AttributeKeys.Url))
                         ?? ThreatIndicators.ExtractDomain(evt.Subject);
            var sha256 = evt.Attr(AttributeKeys.Sha256) ?? evt.Attr(AttributeKeys.ContentHash);

            if (feedback.IsFalsePositive)
            {
                _baseline.RecordFalsePositive(evt);
                _reputation.MarkBenign(
                    evt.Category == EventCategory.Process ? processName : null,
                    domain,
                    sha256);
            }
            else
            {
                // Menace confirmée : renforce la réputation locale négative
                if (!string.IsNullOrWhiteSpace(sha256)) _reputation.MarkBadHash(sha256);
                if (!string.IsNullOrWhiteSpace(domain)) _reputation.MarkBadDomain(domain);
                var ip = evt.Attr(AttributeKeys.RemoteIp) ?? evt.Attr(AttributeKeys.SourceIp);
                if (ThreatIndicators.IsPublicIp(ip)) _reputation.MarkBadIp(ip);
            }
        }

        // Mise à jour probabiliste du modèle markovien (réversible via FeedbackId)
        if (resolvedEvents.Count >= 2)
        {
            var orderedCats = resolvedEvents.OrderBy(e => e.Timestamp).Select(e => e.Category).ToArray();
            _correlation.MarkovModel.ApplyFeedback(feedback.FeedbackId, orderedCats, feedback.IsFalsePositive);
        }

        lock (_contextGate)
        {
            _feedbackHistory.Add(new FeedbackHistoryEntryDto(
                feedback.FeedbackId,
                feedback.RecordedAt,
                "Admin",
                feedback.AlertId,
                feedback.ClusterId,
                feedback.IsFalsePositive,
                feedback.Comment,
                Reverted: false,
                RevertedAt: null));

            if (_feedbackHistory.Count > 500)
            {
                _feedbackHistory.RemoveAt(0);
            }
        }

        _logger.LogInformation("Retour analyste appliqué ({Count} événements, fauxPositif={Fp}, id={Id}).",
            resolvedEvents.Count, feedback.IsFalsePositive, feedback.FeedbackId);
    }

    /// <inheritdoc />
    public IReadOnlyList<FeedbackHistoryEntryDto> GetFeedbackHistory()
    {
        lock (_contextGate)
        {
            return _feedbackHistory.OrderByDescending(f => f.RecordedAt).ToArray();
        }
    }

    /// <inheritdoc />
    public bool RevertFeedback(Guid feedbackId)
    {
        var revertedMarkov = _correlation.MarkovModel.RevertFeedback(feedbackId);
        lock (_contextGate)
        {
            var idx = _feedbackHistory.FindIndex(f => f.Id == feedbackId && !f.Reverted);
            if (idx < 0) return revertedMarkov;
            _feedbackHistory[idx] = _feedbackHistory[idx] with
            {
                Reverted = true,
                RevertedAt = _clock.GetUtcNow()
            };
            return true;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<CorrelationCluster> GetActiveClusters(string? hostId = null) =>
        _correlation.GetActiveClusters(hostId);

    /// <inheritdoc />
    public CorrelationCluster? GetCluster(Guid clusterId) =>
        _correlation.GetCluster(clusterId);

    /// <inheritdoc />
    public BaselineSummaryDto? GetBaseline(string hostId, string? userId = null) =>
        _baseline.GetSummary(hostId, userId);

    /// <inheritdoc />
    public Task WarmUpAsync(IEnumerable<ScoredEvent> recentEvents, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(recentEvents);
        var settings = _settings;

        foreach (var scored in recentEvents.OrderBy(x => x.Event.Timestamp))
        {
            ct.ThrowIfCancellationRequested();
            var enriched = _preFilter.Evaluate(scored.Event, settings);

            if (scored.Assessment.Score < settings.Thresholds.Low)
            {
                _baseline.Observe(enriched);
            }

            RememberEvent(scored.Event, scored.Assessment);

            if (settings.Correlation.Enabled && scored.Assessment.Score >= settings.Correlation.MinEventScore)
            {
                _correlation.Correlate(enriched, scored.Assessment, settings);
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public string ExportBaseline() => _baseline.ExportJson();

    /// <inheritdoc />
    public void ImportBaseline(string json) => _baseline.ImportJson(json);

    private static ThreatAssessment ApplyContextualPromotion(
        SecurityEvent evt,
        EnrichedEvent enriched,
        ThreatAssessment assessment,
        IReadOnlyList<RecentEventSummary> recentContext)
    {
        if (recentContext.Count == 0) return assessment;

        // Connexion réussie suivant des échecs d'authentification récents (< 10 min) même sans failure.count renseigné
        if (evt.Category == EventCategory.Session &&
            evt.EventType == EventTypes.LogonSuccess &&
            assessment.Score < 50)
        {
            var recentFailures = recentContext.Count(r =>
                r.Category == EventCategory.Session &&
                r.EventType == EventTypes.LogonFailure &&
                (evt.Timestamp - r.Timestamp).Duration() <= TimeSpan.FromMinutes(10));

            if (recentFailures >= 2)
            {
                var rules = assessment.MatchedRules.Append("SESS-LOGON-AFTER-FAILURES").Distinct().ToArray();
                var mitre = assessment.MitreTechniques.Concat(["T1110", "T1078"]).Distinct().ToArray();
                return assessment with
                {
                    Score = Math.Max(assessment.Score, 55),
                    Type = ThreatType.Intrusion,
                    Justification = $"Connexion réussie immédiatement après {recentFailures} échecs d'authentification récents.",
                    MatchedRules = rules,
                    MitreTechniques = mitre
                };
            }
        }

        // Lancement d'un shell/LOLBin juste après une anomalie de frappe/BadUSB (< 3 min)
        if (evt.Category == EventCategory.Process &&
            evt.EventType == EventTypes.ProcessStart &&
            enriched.IsLolBin &&
            assessment.Score < 42)
        {
            var recentBadUsb = recentContext.Any(r =>
                r.ThreatType == ThreatType.BadUsb &&
                r.Score >= 30 &&
                (evt.Timestamp - r.Timestamp).Duration() <= TimeSpan.FromMinutes(3));

            if (recentBadUsb)
            {
                var rules = assessment.MatchedRules.Append("PROC-LOLBIN-AFTER-HID").Distinct().ToArray();
                var mitre = assessment.MitreTechniques.Concat(["T1059.001"]).Distinct().ToArray();
                return assessment with
                {
                    Score = Math.Max(assessment.Score, 48),
                    Type = ThreatType.BadUsb,
                    Justification = $"Lancement d'interpréteur ({enriched.ProcessName}) immédiatement après activité HID/frappe suspecte.",
                    MatchedRules = rules,
                    MitreTechniques = mitre
                };
            }
        }

        return assessment;
    }

    private IReadOnlyList<RecentEventSummary> GetRecentContext(string hostId, DateTimeOffset referenceTime)
    {
        var cutoff = referenceTime - TimeSpan.FromMinutes(30);
        lock (_contextGate)
        {
            if (!_recentByHost.TryGetValue(hostId, out var list) || list.Count == 0)
            {
                return Array.Empty<RecentEventSummary>();
            }

            var result = new List<RecentEventSummary>(Math.Min(list.Count, 20));
            for (var node = list.Last; node is not null && result.Count < 20; node = node.Previous)
            {
                if (node.Value.Timestamp >= cutoff && node.Value.Timestamp <= referenceTime + TimeSpan.FromMinutes(1))
                {
                    result.Add(node.Value);
                }
            }
            result.Reverse();
            return result;
        }
    }

    private void RememberEvent(SecurityEvent evt, ThreatAssessment assessment)
    {
        var summary = new RecentEventSummary(
            evt.Timestamp,
            evt.Category,
            evt.EventType,
            evt.Subject,
            assessment.Score,
            assessment.Type);

        lock (_contextGate)
        {
            // Cache d'historique borné pour ApplyFeedback
            if (!_eventLookup.ContainsKey(evt.Id))
            {
                _eventLookup[evt.Id] = evt;
                _eventLookupOrder.Enqueue(evt.Id);
                while (_eventLookupOrder.Count > MaxEventHistoryCache)
                {
                    var oldId = _eventLookupOrder.Dequeue();
                    _eventLookup.Remove(oldId);
                }
            }

            if (!_recentByHost.TryGetValue(evt.HostId, out var list))
            {
                if (_recentByHost.Count >= MaxRecentHosts)
                {
                    var firstKey = _recentByHost.Keys.First();
                    _recentByHost.Remove(firstKey);
                }
                list = new LinkedList<RecentEventSummary>();
                _recentByHost[evt.HostId] = list;
            }

            list.AddLast(summary);
            while (list.Count > MaxRecentContextPerHost)
            {
                list.RemoveFirst();
            }
        }
    }

    internal static SentinelSettings CloneSettings(SentinelSettings s) => new()
    {
        Thresholds = new ThreatThresholds
        {
            Low = s.Thresholds.Low,
            Moderate = s.Thresholds.Moderate,
            High = s.Thresholds.High,
            Critical = s.Thresholds.Critical
        },
        Mode = s.Mode,
        LearningStartedAt = s.LearningStartedAt,
        LearningPeriodDays = s.LearningPeriodDays,
        AutoLeaveLearning = s.AutoLeaveLearning,
        WatchedFolders = new List<string>(s.WatchedFolders),
        ExcludedProcesses = new List<string>(s.ExcludedProcesses),
        ExcludedDomains = new List<string>(s.ExcludedDomains),
        ExcludedHashes = new List<string>(s.ExcludedHashes),
        ExcludedPaths = new List<string>(s.ExcludedPaths),
        EventRetentionDays = s.EventRetentionDays,
        AlertRetentionDays = s.AlertRetentionDays,
        Llm = new LlmSettings
        {
            Enabled = s.Llm.Enabled,
            Endpoint = s.Llm.Endpoint,
            Model = s.Llm.Model,
            AutoSelectBestQwen = s.Llm.AutoSelectBestQwen,
            EmbeddingModel = s.Llm.EmbeddingModel,
            TimeoutSeconds = s.Llm.TimeoutSeconds,
            AmbiguityLow = s.Llm.AmbiguityLow,
            AmbiguityHigh = s.Llm.AmbiguityHigh,
            MinConfidence = s.Llm.MinConfidence,
            MaxConcurrency = s.Llm.MaxConcurrency,
            KeepAlive = s.Llm.KeepAlive,
            ContextWindow = s.Llm.ContextWindow,
            MaxOutputTokens = s.Llm.MaxOutputTokens,
            EnableResponseCache = s.Llm.EnableResponseCache,
            CacheTtlMinutes = s.Llm.CacheTtlMinutes,
            WarmUpOnStartup = s.Llm.WarmUpOnStartup
        },
        Correlation = new CorrelationSettings
        {
            ShortWindowMinutes = s.Correlation.ShortWindowMinutes,
            MediumWindowMinutes = s.Correlation.MediumWindowMinutes,
            LongWindowHours = s.Correlation.LongWindowHours,
            MinEventScore = s.Correlation.MinEventScore,
            DecayHalfLifeMinutes = s.Correlation.DecayHalfLifeMinutes,
            SameEntityWeight = s.Correlation.SameEntityWeight,
            SameTypeWeight = s.Correlation.SameTypeWeight,
            EarlyEscalation = s.Correlation.EarlyEscalation,
            Enabled = s.Correlation.Enabled
        },
        EnableClipboardMonitoring = s.EnableClipboardMonitoring,
        EnableTypingRhythm = s.EnableTypingRhythm,
        EnableBrowserMonitoring = s.EnableBrowserMonitoring,
        EnableNetworkMonitoring = s.EnableNetworkMonitoring,
        EnableDefenderCollector = s.EnableDefenderCollector,
        EnableSysmonCollector = s.EnableSysmonCollector,
        Canaries = new CanarySettings
        {
            Enabled = s.Canaries.Enabled,
            FilesPerFolder = s.Canaries.FilesPerFolder,
            Folders = new List<string>(s.Canaries.Folders),
            AutoIsolateOnTrigger = s.Canaries.AutoIsolateOnTrigger
        },
        ScriptVisibility = new ScriptVisibilitySettings
        {
            Enabled = s.ScriptVisibility.Enabled,
            EnablePowerShell4104 = s.ScriptVisibility.EnablePowerShell4104,
            EnableEtwAmsi = s.ScriptVisibility.EnableEtwAmsi,
            StoreSanitizedExcerpt = s.ScriptVisibility.StoreSanitizedExcerpt,
            MaxExcerptLength = s.ScriptVisibility.MaxExcerptLength
        },
        ThreatIntel = new ThreatIntelSettings
        {
            Enabled = s.ThreatIntel.Enabled,
            EnableAbuseChFeeds = s.ThreatIntel.EnableAbuseChFeeds,
            EnableOpenPhishCommunity = s.ThreatIntel.EnableOpenPhishCommunity,
            EnablePhishTank = s.ThreatIntel.EnablePhishTank,
            EnableVirusTotalOnDemand = s.ThreatIntel.EnableVirusTotalOnDemand,
            RefreshIntervalHours = s.ThreatIntel.RefreshIntervalHours,
            IndicatorTtlDays = s.ThreatIntel.IndicatorTtlDays
        },
        StaticScan = new StaticScanSettings
        {
            Enabled = s.StaticScan.Enabled,
            ScanOnFileEvent = s.StaticScan.ScanOnFileEvent,
            ScanOnProcessStart = s.StaticScan.ScanOnProcessStart,
            MaxFileSizeBytes = s.StaticScan.MaxFileSizeBytes,
            TimeoutMs = s.StaticScan.TimeoutMs,
            MaxConcurrency = s.StaticScan.MaxConcurrency,
            ScheduledScanIntervalHours = s.StaticScan.ScheduledScanIntervalHours
        },
        Rules = new RulesSettings
        {
            EnableSigma = s.Rules.EnableSigma,
            EnableYara = s.Rules.EnableYara,
            HotReload = s.Rules.HotReload,
            DisabledRuleIds = new List<string>(s.Rules.DisabledRuleIds),
            ExcludedRuleTargets = new List<string>(s.Rules.ExcludedRuleTargets)
        },
        MachineLearning = new MlSettings
        {
            Enabled = s.MachineLearning.Enabled,
            MaxScoreContribution = s.MachineLearning.MaxScoreContribution,
            SuspiciousProbabilityThreshold = s.MachineLearning.SuspiciousProbabilityThreshold
        },
        Notifications = CloneNotifications(s.Notifications),
        Language = s.Language
    };

    private static NotificationSettings CloneNotifications(NotificationSettings? n)
    {
        n ??= new NotificationSettings();
        var email = n.Email ?? new EmailNotificationSettings();
        var wa = n.WhatsApp ?? new WhatsAppNotificationSettings();
        var wh = n.Webhook ?? new WebhookNotificationSettings();

        return new NotificationSettings
        {
            Enabled = n.Enabled,
            CooldownMinutes = n.CooldownMinutes,
            NotifyOnCorrelatedCluster = n.NotifyOnCorrelatedCluster,
            IncludeDashboardUrl = n.IncludeDashboardUrl,
            DashboardBaseUrl = n.DashboardBaseUrl,
            Email = new EmailNotificationSettings
            {
                Enabled = email.Enabled,
                MinLevel = email.MinLevel,
                SmtpHost = email.SmtpHost,
                SmtpPort = email.SmtpPort,
                UseStartTls = email.UseStartTls,
                Username = email.Username,
                FromAddress = email.FromAddress,
                FromName = email.FromName,
                Recipients = new List<string>(email.Recipients ?? [])
            },
            WhatsApp = new WhatsAppNotificationSettings
            {
                Enabled = wa.Enabled,
                MinLevel = wa.MinLevel,
                Provider = wa.Provider,
                PhoneNumberId = wa.PhoneNumberId,
                AccountSid = wa.AccountSid,
                FromNumber = wa.FromNumber,
                ApiVersion = wa.ApiVersion,
                Recipients = new List<string>(wa.Recipients ?? [])
            },
            Webhook = new WebhookNotificationSettings
            {
                Enabled = wh.Enabled,
                MinLevel = wh.MinLevel,
                Format = wh.Format,
                Url = wh.Url,
                TelegramChatId = wh.TelegramChatId
            }
        };
    }
}
