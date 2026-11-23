using System.Globalization;
using System.Text;
using Sentinel.Shared.Models;
using Sentinel.Simulation.Benchmark;

namespace Sentinel.Simulation.Reporting;

/// <summary>
/// Génère un rapport scientifique complet au format Markdown (doc §1.2, §8.4, §14)
/// directement exploitable dans la documentation du projet ou un mémoire académique.
/// </summary>
public static class MarkdownReportWriter
{
    public static string BuildMarkdown(EvaluationReport report)
    {
        var sb = new StringBuilder(8192);
        var inv = CultureInfo.InvariantCulture;

        var sumA = report.Summaries.First(s => s.ConfigKey == "A");
        var sumB = report.Summaries.First(s => s.ConfigKey == "B");
        var sumC = report.Summaries.First(s => s.ConfigKey == "C");

        sb.AppendLine("# SENTINEL — Rapport d'évaluation scientifique (Protocole A vs B vs C)");
        sb.AppendLine();
        sb.AppendLine($"> Généré le **{report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC** — Poste simulé : `{report.HostId}`");
        sb.AppendLine($"> **Moteur IA utilisé (B & C)** : {report.LlmModeLabel}");
        if (!report.UsingRealOllama)
        {
            sb.AppendLine("> *Note méthodologique :* cette exécution repose sur l'évaluateur déterministe local `DeterministicSimulatedLlmAssessor` (sans dépendance réseau). Relancez avec `--ollama --ollama-model qwen2.5-coder:3b` lorsqu'un serveur Ollama local est actif pour mesurer la latence et les scores réels.");
        }
        sb.AppendLine();

        sb.AppendLine("## 1. Hypothèse scientifique évaluée (doc §1.2, §8.4, §14.3)");
        sb.AppendLine();
        sb.AppendLine("> *La corrélation d'événements individuellement faibles réduit le délai de détection d'une chaîne d'attaque (Time-To-Detect) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*");
        sb.AppendLine();
        sb.AppendLine($"Trois configurations sont comparées sur exactement les mêmes {sumC.TotalScenarios} scénarios d'attaque (v1 + v2) et le même corpus bénin de fond sur 24 heures :");
        sb.AppendLine("- **(A) Règles + Sigma seules** : `Llm.Enabled = false`, `Correlation.Enabled = false`.");
        sb.AppendLine("- **(B) Règles + Sigma + IA sans corrélation** : `Llm.Enabled = true`, `Correlation.Enabled = false`.");
        sb.AppendLine("- **(C) SENTINEL v2 Complet** : `Llm.Enabled = true`, `Correlation.Enabled = true`, `EarlyEscalation = true` (graphe Markovien).");
        sb.AppendLine();
        sb.AppendLine("Un scénario est considéré **détecté** dès qu'une décision atteint le niveau **Élevé (≥ 75)** ou déclenche `AlertAdmin = true`.");
        sb.AppendLine();

        sb.AppendLine("## 2. Synthèse des métriques agrégées");
        sb.AppendLine();
        sb.AppendLine("| Configuration | Scénarios détectés | Rappel | Précision | Faux positifs (FPR) | Évts moy. avant alerte | TTD moyen (s) | Latence moy. (ms) | RAM (Mo) | Appels IA |");
        sb.AppendLine("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        foreach (var s in report.Summaries)
        {
            sb.AppendLine(string.Format(
                inv,
                "| **{0}** | {1}/{2} | {3:F1} % | {4:F1} % | {5} ({6:F2} %) | {7:F2} | {8:F2} s | {9:F3} ms | {10:F1} Mo | {11} ({12:F1} %) |",
                s.ConfigurationName,
                s.DetectedCount,
                s.TotalScenarios,
                s.Recall * 100.0,
                s.Precision * 100.0,
                s.FalsePositives,
                s.FalsePositiveRate * 100.0,
                s.AvgEventsBeforeAlertAllDetected,
                s.AvgSecondsToDetectAllDetected,
                s.AvgLatencyMs,
                s.WorkingSetMb,
                s.TotalLlmCalls,
                s.LlmUsageRatio * 100.0));
        }
        sb.AppendLine();

        sb.AppendLine("### Gains mesurés de la configuration (C)");
        sb.AppendLine();
        sb.AppendLine(string.Format(
            inv,
            "- **Gain Time-To-Detect (C vs A, comparaison appariée sur scénarios détectés par A et C)** : `{0:F2} s` → `{1:F2} s`, soit **-{2:F1} %** (et **-{3:F2} événements** en moyenne avant l'alerte).",
            report.PairedAvgTtdA, report.PairedAvgTtdCvsA, report.GainTtdCvsAPercent, report.GainEventsCvsA));
        sb.AppendLine(string.Format(
            inv,
            "- **Gain Time-To-Detect (C vs B, comparaison appariée sur scénarios détectés par B et C)** : `{0:F2} s` → `{1:F2} s`, soit **-{2:F1} %** (et **-{3:F2} événements** en moyenne avant l'alerte).",
            report.PairedAvgTtdB, report.PairedAvgTtdCvsB, report.GainTtdCvsBPercent, report.GainEventsCvsB));
        sb.AppendLine(string.Format(
            inv,
            "- **Gain de rappel (C vs A)** : `{0:F1} %` → `{1:F1} %` (+{2} scénario(s) détecté(s) grâce à la corrélation et au contexte).",
            sumA.Recall * 100.0, sumC.Recall * 100.0, sumC.DetectedCount - sumA.DetectedCount));
        sb.AppendLine(string.Format(
            inv,
            "- **Vérification de la règle du « 2ᵉ événement » (doc §1.1, §8.2-5, §14.2)** : **{0}** (moyenne sur les chaînes multi-étapes en config C : `{1:F2}` événements).",
            report.SecondEventHypothesisVerified ? "VALIDÉE (100 % des chaînes multi-étapes alertent dès le 2ᵉ événement)" : "PARTIELLE",
            sumC.AvgEventsBeforeAlertMultiStage));
        sb.AppendLine(string.Format(
            inv,
            "- **Taux de faux positifs (corpus bénin de {0} événements)** : `{1}` FP en (A), `{2}` FP en (B), `{3}` FP en (C) — FPR = **{4:F2} %**.",
            report.BenignEventCount, sumA.FalsePositives, sumB.FalsePositives, sumC.FalsePositives, sumC.FalsePositiveRate * 100.0));
        sb.AppendLine();

        sb.AppendLine("## 3. Résultats détaillés par scénario et mapping MITRE ATT&CK");
        sb.AppendLine();
        sb.AppendLine("| Scénario | Techniques MITRE ATT&CK | (A) Règles seules | (B) Règles + IA | (C) Règles + IA + Corrélation | Chaîne corrélée (C) | Gain TTD (C vs A) |");
        sb.AppendLine("|---|---|---|---|---|---|---:|");

        foreach (var group in report.Details.GroupBy(d => d.ScenarioId))
        {
            var a = group.First(x => x.ConfigKey == "A");
            var b = group.First(x => x.ConfigKey == "B");
            var c = group.First(x => x.ConfigKey == "C");
            var mitre = string.Join(", ", a.MitreTechniques.Select(t => $"`{t}`"));

            var gain = !c.Detected ? "—"
                : !a.Detected ? "**Détecté (manqué par A)**"
                : a.SecondsToDetect <= 0.001 ? "0 % (IOC connu)"
                : string.Format(inv, "**-{0:F1} %** (-{1:F1} s)", ((a.SecondsToDetect - c.SecondsToDetect) / a.SecondsToDetect) * 100.0, a.SecondsToDetect - c.SecondsToDetect);

            sb.AppendLine(
                $"| **{a.ScenarioName}** | {mitre} | {FormatMdCell(a)} | {FormatMdCell(b)} | {FormatMdCell(c)} | {c.DetectedChainName ?? "Signature directe"} | {gain} |");
        }
        sb.AppendLine();

        sb.AppendLine("## 4. Tableau complet (Scénario × Configuration)");
        sb.AppendLine();
        sb.AppendLine("| Scénario | Configuration | Détecté | Évts avant alerte | TTD (s) | Score pic | Niveau 1ʳᵉ alerte | Déclencheur | Escalade précoce | Latence (ms) |");
        sb.AppendLine("|---|---|---|---:|---:|---:|---|---|---|---:|");

        foreach (var d in report.Details)
        {
            sb.AppendLine(string.Format(
                inv,
                "| {0} | {1} | {2} | {3} | {4} | {5}/100 | {6} | {7} | {8} | {9:F3} |",
                d.ScenarioName,
                d.ConfigurationName,
                d.Detected ? "Oui" : "**Non**",
                d.Detected ? $"{d.EventsBeforeAlert}/{d.TotalAttackEvents}" : "—",
                d.Detected ? d.SecondsToDetect.ToString("F2", inv) : "—",
                d.PeakScore,
                d.Detected ? ThreatLevels.Label(d.FirstAlertLevel) : "—",
                d.FirstAlertTriggerEvent ?? "—",
                d.EarlyEscalated ? "Oui (+1 niv.)" : "Non",
                d.AvgLatencyMs));
        }
        sb.AppendLine();

        sb.AppendLine("## 5. Corpus de trafic bénin et maîtrise des faux positifs");
        sb.AppendLine();
        sb.AppendLine($"Le corpus bénin comporte **{report.BenignEventCount} événements** simulant une journée complète de **24 heures** (00h00–23h59) :");
        sb.AppendLine("- Activité bureautique de journée (08h30–17h30) : processus signés Microsoft/Google/Mozilla, domaines habituels, fichiers bureautiques basse entropie, dynamique de saisie humaine (~5 touches/s, σ ≈ 45 ms), cycle de session et erreur isolée de mot de passe.");
        sb.AppendLine("- Activité de fond sur 24 h (nuit et soirée) : mises à jour Windows/Defender (`MsMpEng.exe`, `UsoClient.exe`), synchronisation `OneDrive.exe`, indexation `SearchIndexer.exe`, résolutions DNS légitimes et blocs PowerShell d'administration non obfusqués.");
        sb.AppendLine();
        sb.AppendLine(string.Format(
            inv,
            "Sur ce corpus, l'appel sélectif au LLM (bande ambiguë 25–80) n'est sollicité que sur **{0:F1} %** des événements totaux, garantissant un taux de faux positifs de **{1:F2} %** et une latence moyenne de **{2:F3} ms/événement**.",
            sumC.LlmUsageRatio * 100.0, sumC.FalsePositiveRate * 100.0, sumC.AvgLatencyMs));
        sb.AppendLine();

        return sb.ToString();
    }

    public static async Task WriteFileAsync(string path, EvaluationReport report, CancellationToken ct = default)
    {
        var fullPath = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(fullPath, BuildMarkdown(report), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), ct)
            .ConfigureAwait(false);
    }

    private static string FormatMdCell(ScenarioRunDetail d)
    {
        if (!d.Detected)
        {
            return $"Non détecté (pic {d.PeakScore})";
        }

        var esc = d.EarlyEscalated ? " *(escalade)*" : string.Empty;
        return string.Format(
            CultureInfo.InvariantCulture,
            "Evt **#{0}**/{1} — **{2:F1} s** (pic {3}){4}",
            d.EventsBeforeAlert,
            d.TotalAttackEvents,
            d.SecondsToDetect,
            d.PeakScore,
            esc);
    }
}
