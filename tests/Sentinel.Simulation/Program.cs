using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Sentinel.Shared.Json;
using Sentinel.Simulation;
using Sentinel.Simulation.Ai;
using Sentinel.Simulation.Benchmark;
using Sentinel.Simulation.Replay;
using Sentinel.Simulation.Reporting;

Console.OutputEncoding = Encoding.UTF8;

var options = CliOptions.Parse(args, out var parseError);
if (parseError is not null)
{
    Console.Error.WriteLine($"[ERREUR] {parseError}");
    Console.WriteLine();
    CliOptions.PrintUsage();
    return 1;
}

if (options.ShowHelp)
{
    CliOptions.PrintUsage();
    return 0;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

try
{
    // Mode 1 : Rejeu gRPC temps réel vers Sentinel.Server
    if (options.IsGrpcReplayMode)
    {
        return await GrpcLiveReplayer.RunAsync(options, cts.Token).ConfigureAwait(false);
    }

    // Mode 2 (par défaut) : Benchmark scientifique A vs B vs C (+ exports JSON / Markdown / API REST)
    var resolvedLlm = await LlmAssessorResolver.ResolveAsync(options, cts.Token).ConfigureAwait(false);
    var runner = new BenchmarkRunner();
    var report = await runner.RunAsync(options, resolvedLlm, cts.Token).ConfigureAwait(false);

    ConsoleReportPrinter.Print(report, resolvedLlm.WarningMessage);

    var metricDtos = report.ToScenarioMetricDtos();

    if (!string.IsNullOrWhiteSpace(options.OutputJsonPath))
    {
        var fullJsonPath = Path.GetFullPath(options.OutputJsonPath);
        var jsonDir = Path.GetDirectoryName(fullJsonPath);
        if (!string.IsNullOrEmpty(jsonDir)) Directory.CreateDirectory(jsonDir);

        var prettyOptions = SentinelJson.Create();
        prettyOptions.WriteIndented = true;
        prettyOptions.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        var json = JsonSerializer.Serialize(metricDtos, prettyOptions);
        await File.WriteAllTextAsync(fullJsonPath, json, new UTF8Encoding(false), cts.Token).ConfigureAwait(false);
        Console.WriteLine($"  [EXPORT] JSON ScenarioMetricDto[] écrit : {fullJsonPath}");
    }

    if (!string.IsNullOrWhiteSpace(options.OutputMdPath))
    {
        var fullMdPath = Path.GetFullPath(options.OutputMdPath);
        await MarkdownReportWriter.WriteFileAsync(fullMdPath, report, cts.Token).ConfigureAwait(false);
        Console.WriteLine($"  [EXPORT] Rapport Markdown écrit         : {fullMdPath}");
    }

    if (!string.IsNullOrWhiteSpace(options.PushEvalUrl))
    {
        var pushed = await EvaluationApiPusher.PushAsync(
            options.PushEvalUrl,
            options.BearerToken,
            metricDtos,
            cts.Token).ConfigureAwait(false);

        if (!pushed) return 2;
    }

    return 0;
}
catch (OperationCanceledException)
{
    Console.WriteLine("\n  [INFO] Exécution interrompue par l'utilisateur.");
    return 130;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ERREUR FATALE] {ex.Message}");
    return 1;
}
