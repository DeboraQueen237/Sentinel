using System.Diagnostics;
using Sentinel.AI;
using Sentinel.Shared.Models;

namespace Sentinel.Simulation.Ai;

/// <summary>
/// Évaluateur IA local simulé de façon déterministe (sans dépendance réseau) reproduisant
/// le comportement d'un analyste SOC LLM local (type <c>qwen2.5:7b</c>) recevant un événement
/// ambigu accompagné de son contexte récent sur 30 min et de la baseline utilisateur (doc §7.3).
/// </summary>
public sealed class DeterministicSimulatedLlmAssessor : ILlmAssessor
{
    private long _calls;
    private long _successes;
    private long _totalLatencyMicros;
    private volatile bool _enabled = true;

    public bool IsAvailable => _enabled;

    public LlmMetrics Metrics
    {
        get
        {
            var calls = Interlocked.Read(ref _calls);
            var successes = Interlocked.Read(ref _successes);
            var totalMicros = Interlocked.Read(ref _totalLatencyMicros);
            var avgMs = calls > 0 ? Math.Round((totalMicros / 1000.0) / calls, 3) : 0.0;
            return new LlmMetrics(calls, successes, 0, avgMs, _enabled, DateTimeOffset.UtcNow, null);
        }
    }

    public void UpdateSettings(LlmSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _enabled = settings.Enabled;
    }

    public Task<bool> CheckHealthAsync(CancellationToken ct = default) => Task.FromResult(_enabled);

    public Task<float[]?> GetEmbeddingAsync(string text, CancellationToken ct = default) =>
        Task.FromResult<float[]?>(null);

    public Task<LlmAssessmentResult?> AssessAsync(LlmScoringContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!_enabled) return Task.FromResult<LlmAssessmentResult?>(null);

        var start = Stopwatch.GetTimestamp();
        Interlocked.Increment(ref _calls);

        var evt = context.Event;
        var recentCutoff = evt.Timestamp - TimeSpan.FromMinutes(10);
        var priorSuspicious = context.RecentEvents
            .Where(r => r.Score >= 30 && r.Timestamp >= recentCutoff && r.Timestamp <= evt.Timestamp)
            .ToList();

        var ruleSet = new HashSet<string>(context.MatchedRules, StringComparer.OrdinalIgnoreCase);
        var threatType = context.RuleType;
        int score;
        double confidence;
        string justification;

        // 1. Signal faible isolé (aucun signal suspect dans les 10 dernières minutes)
        //    Un analyste prudent évite les faux positifs sur un événement isolé.
        if (priorSuspicious.Count == 0)
        {
            if (evt.Category == EventCategory.Session &&
                evt.EventType == EventTypes.LogonFailure &&
                (evt.AttrLong(AttributeKeys.FailureCount) ?? 1) <= 1 &&
                evt.Timestamp.Hour is >= 7 and <= 20)
            {
                score = Math.Max(18, context.RuleScore - 10);
                confidence = 0.72;
                justification = "Échec d'authentification isolé en horaire ouvré, compatible avec une erreur de saisie utilisateur.";
            }
            else
            {
                score = Math.Clamp(context.RuleScore, 20, 62);
                confidence = 0.72;
                justification = $"Signal faible isolé ({evt.Category}/{evt.EventType}) sans précurseur suspect dans les 10 dernières minutes ; surveillance maintenue.";
            }
        }
        else
        {
            // 2. Analyse contextuelle multi-événements à partir du résumé récent (sans graphe de corrélation)
            var categoriesSeen = priorSuspicious.Select(r => r.Category).Distinct().Count();
            var hasPriorClipboardOrBrowser = priorSuspicious.Any(r => r.Category is EventCategory.Clipboard or EventCategory.Browser);
            var hasPriorUsbHid = priorSuspicious.Any(r => r.Category == EventCategory.Device && r.ThreatType == ThreatType.BadUsb);
            var hasPriorTempProc = priorSuspicious.Any(r => r.Category == EventCategory.Process);
            var hasPriorHighEntropy = priorSuspicious.Any(r => r.Category == EventCategory.File && r.ThreatType == ThreatType.Ransomware);
            var hasPriorArchive = priorSuspicious.Any(r => r.Category == EventCategory.File && r.ThreatType == ThreatType.Exfiltration);
            var hasPriorFailures = priorSuspicious.Count(r => r.Category == EventCategory.Session && r.EventType == EventTypes.LogonFailure);
            var hasPriorInstallOrStartup = priorSuspicious.Any(r => r.Category == EventCategory.Installation);

            if (priorSuspicious.Count >= 2 && IsStrongConfirmationStep(evt, ruleSet, hasPriorClipboardOrBrowser,
                hasPriorTempProc, hasPriorHighEntropy, hasPriorArchive, hasPriorFailures, hasPriorInstallOrStartup))
            {
                // 3e étape ou plus confirmant sémantiquement une chaîne d'attaque cohérente
                score = Math.Clamp(Math.Max(context.RuleScore + 22, 85), 82, 92);
                confidence = 0.86;
                justification = BuildContextualJustification(evt, priorSuspicious.Count, categoriesSeen, confirmed: true);
            }
            else if (priorSuspicious.Count == 1)
            {
                // 2e signal suspect observé dans la fenêtre : l'IA seule relève prudemment la vigilance
                // (niveau Modéré, sans certitude suffisante pour alerter l'administrateur sans moteur de corrélation formel)
                var boost = hasPriorUsbHid && evt.Category == EventCategory.Typing ? 4 :
                            hasPriorInstallOrStartup && evt.EventType == EventTypes.StartupEntryAdded ? 14 :
                            hasPriorTempProc && evt.Category == EventCategory.File ? 24 :
                            hasPriorArchive && evt.Category == EventCategory.Device ? 24 :
                            14;

                score = Math.Clamp(context.RuleScore + boost, 52, 74);
                confidence = 0.74;
                justification = BuildContextualJustification(evt, priorSuspicious.Count, categoriesSeen, confirmed: false);
            }
            else
            {
                // Plusieurs signaux suspects récents : suspicion forte mais graduée
                score = Math.Clamp(context.RuleScore + 18, 72, 88);
                confidence = 0.82;
                justification = BuildContextualJustification(evt, priorSuspicious.Count, categoriesSeen, confirmed: score >= 82);
            }
        }

        var elapsedMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        Interlocked.Add(ref _totalLatencyMicros, (long)Math.Max(1, Math.Round(elapsedMs * 1000.0)));
        Interlocked.Increment(ref _successes);

        return Task.FromResult<LlmAssessmentResult?>(
            new LlmAssessmentResult(score, threatType, justification, confidence, Math.Round(elapsedMs, 3)));
    }

    private static bool IsStrongConfirmationStep(
        SecurityEvent evt,
        HashSet<string> rules,
        bool hasPriorClipboardOrBrowser,
        bool hasPriorTempProc,
        bool hasPriorHighEntropy,
        bool hasPriorArchive,
        int hasPriorFailures,
        bool hasPriorInstallOrStartup)
    {
        // Téléchargement d'exécutable / double extension ou multi-redirection TLD à risque après navigation suspecte
        if (hasPriorClipboardOrBrowser &&
            (rules.Contains("BROW-EXE-DOWNLOAD") ||
             rules.Contains("BROW-MULTI-REDIRECT") ||
             rules.Contains("FILE-DOUBLE-EXT") ||
             rules.Contains("FILE-EXECUTABLE-DOWNLOAD")))
        {
            return true;
        }

        // Renommage ransomware (.locked) après processus Temp + écriture haute entropie
        if ((hasPriorTempProc || hasPriorHighEntropy) &&
            (rules.Contains("FILE-SUSPICIOUS-RENAME") || rules.Contains("FILE-RANSOMWARE-BURST")))
        {
            return true;
        }

        // Résolution DNS / transfert vers domaine rare ou TLD à risque après archive volumineuse
        if (hasPriorArchive &&
            evt.Category == EventCategory.Network &&
            (rules.Contains("NET-RARE-DOMAIN") || rules.Contains("NET-RISKY-TLD") || rules.Contains("NET-LARGE-OUTBOUND")))
        {
            return true;
        }

        // Rafale d'échecs de connexion répétés (>= 3)
        if (hasPriorFailures >= 2 &&
            evt.Category == EventCategory.Session &&
            evt.EventType is EventTypes.LogonFailure or EventTypes.LogonSuccess)
        {
            return true;
        }

        // Tâche planifiée suspecte après installation non signée + clé Run
        if (hasPriorInstallOrStartup && rules.Contains("PERS-SCHEDULED-TASK"))
        {
            return true;
        }

        return false;
    }

    private static string BuildContextualJustification(
        SecurityEvent evt,
        int priorCount,
        int distinctCategories,
        bool confirmed)
    {
        return confirmed
            ? $"Analyse IA contextuelle : {evt.Category}/{evt.EventType} confirme une séquence malveillante cohérente après {priorCount} signaux suspects ({distinctCategories} catégorie(s)) dans les 10 dernières minutes."
            : $"Analyse IA contextuelle : vigilance accrue sur {evt.Category}/{evt.EventType} suite à {priorCount} signal(aux) faible(s) récent(s), mais contexte encore partiel sans corrélation formelle.";
    }
}

/// <summary>
/// Résout l'évaluateur LLM à utiliser pour le benchmark : Ollama local réel si <c>--ollama</c> est demandé
/// et disponible, sinon repli transparent sur <see cref="DeterministicSimulatedLlmAssessor"/>.
/// </summary>
public static class LlmAssessorResolver
{
    public sealed record ResolvedAssessor(
        Func<LlmSettings, ILlmAssessor> Factory,
        bool UsingRealOllama,
        string ModeLabel,
        string? WarningMessage);

    public static async Task<ResolvedAssessor> ResolveAsync(CliOptions options, CancellationToken ct)
    {
        if (!options.UseOllama)
        {
            return new ResolvedAssessor(
                _ => new DeterministicSimulatedLlmAssessor(),
                UsingRealOllama: false,
                ModeLabel: "DeterministicSimulatedLlmAssessor (analyste IA local simulé déterministe, 0 dépendance réseau)",
                WarningMessage: null);
        }

        var probeSettings = new LlmSettings
        {
            Enabled = true,
            Endpoint = options.OllamaUrl,
            Model = options.OllamaModel,
            TimeoutSeconds = 5
        };

        using var probe = new OllamaAssessor(settings: probeSettings);
        var healthy = await probe.CheckHealthAsync(ct).ConfigureAwait(false);
        if (healthy)
        {
            return new ResolvedAssessor(
                settings =>
                {
                    var assessor = new OllamaAssessor(settings: settings);
                    // Pré-initialise l'état de disponibilité pour que HybridScorer invoque immédiatement Ollama
                    assessor.CheckHealthAsync(CancellationToken.None).GetAwaiter().GetResult();
                    return assessor;
                },
                UsingRealOllama: true,
                ModeLabel: $"Ollama local réel ({options.OllamaModel} @ {options.OllamaUrl})",
                WarningMessage: null);
        }

        return new ResolvedAssessor(
            _ => new DeterministicSimulatedLlmAssessor(),
            UsingRealOllama: false,
            ModeLabel: $"DeterministicSimulatedLlmAssessor (repli automatique — Ollama indisponible ou modèle '{options.OllamaModel}' absent sur {options.OllamaUrl})",
            WarningMessage: $"Ollama indisponible sur {options.OllamaUrl} (modèle '{options.OllamaModel}') : bascule automatique sur DeterministicSimulatedLlmAssessor.");
    }
}
