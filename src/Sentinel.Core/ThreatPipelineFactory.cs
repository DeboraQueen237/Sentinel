using Microsoft.Extensions.Logging;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Shared.Models;

namespace Sentinel.Core;

/// <summary>
/// Fabrique sans conteneur DI pour instancier <see cref="IThreatPipeline"/>
/// (utilisée par la simulation A/B/C et les tests unitaires).
/// </summary>
public static class ThreatPipelineFactory
{
    public static IThreatPipeline Create(
        SentinelSettings settings,
        ILlmAssessor? llm = null,
        ILoggerFactory? loggerFactory = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var effectiveLlm = llm ?? new OllamaAssessor(
            httpClient: null,
            settings: settings.Llm,
            logger: loggerFactory?.CreateLogger<OllamaAssessor>(),
            clock: clock);

        return new ThreatPipeline(settings, effectiveLlm, loggerFactory, clock);
    }
}
