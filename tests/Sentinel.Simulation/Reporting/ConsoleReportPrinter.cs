using System.Globalization;
using Sentinel.Shared.Models;
using Sentinel.Simulation.Benchmark;

namespace Sentinel.Simulation.Reporting;

/// <summary>
/// Affiche en console un tableau comparatif coloré et une synthèse scientifique des résultats A vs B vs C.
/// </summary>
public static class ConsoleReportPrinter
{
    public static void Print(EvaluationReport report, string? warningMessage = null)
    {
        var useColor = !Console.IsOutputRedirected;

        WriteLineColored(new string('═', 114), ConsoleColor.DarkCyan, useColor);
        WriteLineColored("  SENTINEL — Banc d'évaluation scientifique A vs B vs C (doc §1.2, §8.4, §14.3)", ConsoleColor.Cyan, useColor);
        WriteLineColored(new string('═', 114), ConsoleColor.DarkCyan, useColor);
        Console.WriteLine($"  Date (UTC)       : {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"  Poste évalué     : {report.HostId}");
        Console.WriteLine($"  Corpus bénin     : {report.BenignEventCount} événements réalistes (baseline comportementale + mesure FPR)");
        WriteColored("  Moteur IA (B/C)  : ", ConsoleColor.Gray, useColor);
        WriteLineColored(report.LlmModeLabel, report.UsingRealOllama ? ConsoleColor.Green : ConsoleColor.Yellow, useColor);

        if (!string.IsNullOrWhiteSpace(warningMessage))
        {
            WriteLineColored($"  [!] {warningMessage}", ConsoleColor.Yellow, useColor);
        }

        Console.WriteLine();
        WriteLineColored("  1. COMPARAISON PAR SCÉNARIO D'ATTAQUE (A : Règles | B : Règles + IA | C : Règles + IA + Corrélation)", ConsoleColor.White, useColor);
        Console.WriteLine(new string('─', 114));
        Console.WriteLine($"  {"Scénario",-30} | {"(A) Règles seules",-21} | {"(B) Règles + IA",-21} | {"(C) Règles+IA+Corr.",-24} | {"Gain C/A",8}");
        Console.WriteLine(new string('─', 114));

        var scenarioGroups = report.Details
            .GroupBy(d => d.ScenarioId)
            .ToList();

        foreach (var group in scenarioGroups)
        {
            var a = group.First(x => x.ConfigKey == "A");
            var b = group.First(x => x.ConfigKey == "B");
            var c = group.First(x => x.ConfigKey == "C");

            Console.Write($"  {Truncate(a.ScenarioName, 30),-30} | ");
            WriteCell(FormatCompactCell(a), a.Detected ? ConsoleColor.Gray : ConsoleColor.Red, 21, useColor);
            Console.Write(" | ");
            WriteCell(FormatCompactCell(b), b.Detected ? ConsoleColor.Cyan : ConsoleColor.Red, 21, useColor);
            Console.Write(" | ");
            var cColor = c.Detected && (!a.Detected || c.EventsBeforeAlert < a.EventsBeforeAlert || c.SecondsToDetect < a.SecondsToDetect)
                ? ConsoleColor.Green
                : (c.Detected ? ConsoleColor.DarkGreen : ConsoleColor.Red);
            WriteCell(FormatCompactCell(c), cColor, 24, useColor);
            Console.Write(" | ");

            var gainText = FormatScenarioGain(a, c);
            var gainColor = gainText.StartsWith('-') || gainText == "Détecté!"
                ? ConsoleColor.Green
                : ConsoleColor.DarkGray;
            WriteLineColored(gainText.PadLeft(8), gainColor, useColor);
        }

        Console.WriteLine(new string('─', 114));
        Console.WriteLine();

        WriteLineColored("  2. MÉTRIQUES AGRÉGÉES PAR CONFIGURATION", ConsoleColor.White, useColor);
        Console.WriteLine(new string('─', 114));
        Console.WriteLine($"  {"Configuration",-30} | {"Dét.",5} | {"Rappel",7} | {"Préc.",7} | {"FP (FPR)",11} | {"Evts moy",8} | {"TTD moy",8} | {"Latence",8} | {"RAM",7}");
        Console.WriteLine(new string('─', 114));

        foreach (var s in report.Summaries)
        {
            var rowColor = s.ConfigKey switch
            {
                "C" => ConsoleColor.Green,
                "B" => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            var fpStr = string.Format(CultureInfo.InvariantCulture, "{0} ({1:F2}%)", s.FalsePositives, s.FalsePositiveRate * 100.0);
            var line = string.Format(
                CultureInfo.InvariantCulture,
                "  {0,-30} | {1,2}/{2,-2} | {3,6:F1}% | {4,6:F1}% | {5,11} | {6,8:F2} | {7,6:F2} s | {8,5:F2} ms | {9,4:F0} Mo",
                Truncate(s.ConfigurationName, 30),
                s.DetectedCount,
                s.TotalScenarios,
                s.Recall * 100.0,
                s.Precision * 100.0,
                fpStr,
                s.AvgEventsBeforeAlertAllDetected,
                s.AvgSecondsToDetectAllDetected,
                s.AvgLatencyMs,
                s.WorkingSetMb);

            WriteLineColored(line, rowColor, useColor);
        }

        Console.WriteLine(new string('─', 114));
        Console.WriteLine();

        var inv = CultureInfo.InvariantCulture;
        WriteLineColored("  3. SYNTHÈSE SCIENTIFIQUE & VÉRIFICATION DE L'HYPOTHÈSE (§1.2, §8.4, §14.2)", ConsoleColor.White, useColor);
        WriteLineColored(
            string.Format(inv, "  • Gain Time-To-Detect (C vs A, scénarios appariés) : {0:F2} s → {1:F2} s (-{2:F1} %, -{3:F2} événements en moyenne)",
                report.PairedAvgTtdA, report.PairedAvgTtdCvsA, report.GainTtdCvsAPercent, report.GainEventsCvsA),
            ConsoleColor.Green, useColor);
        WriteLineColored(
            string.Format(inv, "  • Gain Time-To-Detect (C vs B, scénarios appariés) : {0:F2} s → {1:F2} s (-{2:F1} %, -{3:F2} événements en moyenne)",
                report.PairedAvgTtdB, report.PairedAvgTtdCvsB, report.GainTtdCvsBPercent, report.GainEventsCvsB),
            ConsoleColor.Green, useColor);

        var cSummary = report.Summaries.First(s => s.ConfigKey == "C");
        WriteLineColored(
            $"  • Hypothèse du « 2ᵉ événement » (chaînes multi-étapes) : {(report.SecondEventHypothesisVerified ? "VALIDÉE (alerte dès le 2ᵉ événement sur 100 % des chaînes, moy. " + cSummary.AvgEventsBeforeAlertMultiStage.ToString("F2", inv) + " évts)" : "PARTIELLE (moy. " + cSummary.AvgEventsBeforeAlertMultiStage.ToString("F2", inv) + " évts)")}",
            report.SecondEventHypothesisVerified ? ConsoleColor.Green : ConsoleColor.Yellow, useColor);

        WriteLineColored(
            string.Format(inv, "  • Maîtrise des faux positifs sur corpus bénin ({0} évts) : {1} FP (FPR = {2:F2} %) — Précision = {3:F1} %",
                report.BenignEventCount, cSummary.FalsePositives, cSummary.FalsePositiveRate * 100.0, cSummary.Precision * 100.0),
            cSummary.FalsePositives == 0 ? ConsoleColor.Green : ConsoleColor.Yellow, useColor);

        WriteLineColored(new string('═', 114), ConsoleColor.DarkCyan, useColor);
    }

    private static string FormatCompactCell(ScenarioRunDetail d)
    {
        if (!d.Detected)
        {
            return $"Non dét. (max {d.PeakScore})";
        }

        var esc = d.EarlyEscalated ? "*" : string.Empty;
        return string.Format(
            CultureInfo.InvariantCulture,
            "Evt #{0}{1} ({2:F0}s) [{3}]",
            d.EventsBeforeAlert,
            esc,
            d.SecondsToDetect,
            d.PeakScore);
    }

    private static string FormatScenarioGain(ScenarioRunDetail a, ScenarioRunDetail c)
    {
        if (!c.Detected) return "—";
        if (!a.Detected) return "Détecté!";
        if (a.SecondsToDetect <= 0.001) return "0 %";

        var pct = ((a.SecondsToDetect - c.SecondsToDetect) / a.SecondsToDetect) * 100.0;
        return pct >= 0.5
            ? string.Format(CultureInfo.InvariantCulture, "-{0:F0}%", pct)
            : "0 %";
    }

    private static void WriteCell(string text, ConsoleColor color, int width, bool useColor)
    {
        var padded = Truncate(text, width).PadRight(width);
        WriteColored(padded, color, useColor);
    }

    private static void WriteColored(string text, ConsoleColor color, bool useColor)
    {
        if (!useColor)
        {
            Console.Write(text);
            return;
        }
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = prev;
    }

    private static void WriteLineColored(string text, ConsoleColor color, bool useColor)
    {
        WriteColored(text, color, useColor);
        Console.WriteLine();
    }

    private static string Truncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..(maxLen - 1)] + "…";
}
