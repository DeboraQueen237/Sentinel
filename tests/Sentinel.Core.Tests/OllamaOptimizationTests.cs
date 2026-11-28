using System.Net;
using System.Text.Json;
using Sentinel.AI;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

public sealed class OllamaOptimizationTests
{
    [Fact]
    public void ModelSelector_PrefersBestLocalQwenWithinHostRamBudget()
    {
        var installed = new List<OllamaInstalledModel>
        {
            new("nomic-embed-text:latest", 274_000_000, "nomic-bert", "137M", "F16"),
            new("llama3.2:3b", 2_000_000_000, "llama", "3.2B", "Q4_K_M"),
            new("qwen2:7b", 4_400_000_000, "qwen2", "7.6B", "Q4_0"),
            new("qwen2.5-coder:3b", 1_900_000_000, "qwen2", "3.1B", "Q4_K_M"),
            new("qwen2.5:14b", 9_000_000_000, "qwen2", "14.8B", "Q4_K_M"),
            new("qwen3:8b", 5_200_000_000, "qwen3", "8.2B", "Q4_K_M"),
            new("qwen2.5:32b", 19_800_000_000, "qwen2", "32.8B", "Q4_K_M")
        };

        // PC 8 Go : budget RAM sûr ≈ 4,4 Go -> qwen2.5-coder:3b (~2,9 Go estimé) gagne sans swap
        var on8Gb = OllamaModelSelector.SelectBestModel(installed, "qwen2.5:7b", autoSelectBestQwen: true, hostRamGb: 8.0);
        on8Gb.SelectedModel.Should().Be("qwen2.5-coder:3b");
        on8Gb.AutoSelected.Should().BeTrue();
        on8Gb.IsQwen.Should().BeTrue();

        // PC 16 Go : budget RAM sûr ≈ 8,8 Go -> qwen3:8b (~7,0 Go estimé) bat qwen2.5-coder:3b et évite 14b/32b
        var on16Gb = OllamaModelSelector.SelectBestModel(installed, "qwen2.5-coder:3b", autoSelectBestQwen: true, hostRamGb: 16.0);
        on16Gb.SelectedModel.Should().Be("qwen3:8b");
        on16Gb.IsQwen.Should().BeTrue();

        // PC 32 Go : budget RAM sûr ≈ 17,6 Go -> qwen2.5:14b ou qwen3:8b dans le budget, 32b exclu pour éviter le swap
        var on32Gb = OllamaModelSelector.SelectBestModel(installed, "qwen2.5-coder:3b", autoSelectBestQwen: true, hostRamGb: 32.0);
        on32Gb.SelectedModel.Should().BeOneOf("qwen3:8b", "qwen2.5:14b");
        on32Gb.SelectedModel.Should().NotBe("qwen2.5:32b");

        // PC 64 Go : budget RAM sûr ≈ 35,2 Go -> qwen2.5:32b ou qwen3:8b selon génération+taille, tous dans budget
        var on64Gb = OllamaModelSelector.SelectBestModel(installed, "qwen2.5-coder:3b", autoSelectBestQwen: true, hostRamGb: 64.0);
        on64Gb.SelectedModel.Should().BeOneOf("qwen2.5:32b", "qwen3:8b", "qwen2.5:14b");
    }

    [Fact]
    public void ModelSelector_IgnoresEmbeddingModels_AndFallsBackWhenNoQwenInstalled()
    {
        var onlyEmbed = new List<OllamaInstalledModel>
        {
            new("nomic-embed-text:latest", 274_000_000, "nomic-bert", "137M", "F16"),
            new("mxbai-embed-large:latest", 670_000_000, "bert", "335M", "F16")
        };

        var none = OllamaModelSelector.SelectBestModel(onlyEmbed, "qwen2.5-coder:3b", autoSelectBestQwen: true, hostRamGb: 16.0);
        none.SelectedModel.Should().BeNull();

        var nonQwen = new List<OllamaInstalledModel>
        {
            new("nomic-embed-text:latest", 274_000_000, "nomic-bert", "137M", "F16"),
            new("mistral:7b", 4_100_000_000, "llama", "7.2B", "Q4_0")
        };

        var fallback = OllamaModelSelector.SelectBestModel(nonQwen, "qwen2.5-coder:3b", autoSelectBestQwen: true, hostRamGb: 16.0);
        fallback.SelectedModel.Should().Be("mistral:7b");
        fallback.IsQwen.Should().BeFalse();
        fallback.AutoSelected.Should().BeTrue();
    }

    [Fact]
    public void ModelSelector_RespectsManualMode_WhenConfiguredModelIsPresent()
    {
        var installed = new List<OllamaInstalledModel>
        {
            new("qwen2.5-coder:3b", 1_900_000_000, "qwen2", "3.1B", "Q4_K_M"),
            new("qwen3:8b", 5_200_000_000, "qwen3", "8.2B", "Q4_K_M")
        };

        var manual = OllamaModelSelector.SelectBestModel(installed, "qwen2.5-coder:3b", autoSelectBestQwen: false, hostRamGb: 16.0);
        manual.SelectedModel.Should().Be("qwen2.5-coder:3b");
        manual.AutoSelected.Should().BeFalse();
    }

    [Fact]
    public void ModelSelector_OnCpuOnlyHost_PrefersFast3BQwenOver9BQwen()
    {
        var installed = new List<OllamaInstalledModel>
        {
            new("qwen3.5:latest", 6_550_000_000, "qwen3", "9.0B", "Q4_K_M"),
            new("qwen2.5-coder:7b", 4_680_000_000, "qwen2", "7.6B", "Q4_K_M"),
            new("qwen2.5-coder:3b", 1_930_000_000, "qwen2", "3.1B", "Q4_K_M")
        };

        // Sans GPU dédié (hasDedicatedGpu: false), qwen2.5-coder:3b gagne pour éviter les timeouts CPU de 70 s
        var cpuChoice = OllamaModelSelector.SelectBestModel(installed, "qwen2.5:7b", autoSelectBestQwen: true, hostRamGb: 15.9, hasDedicatedGpu: false);
        cpuChoice.SelectedModel.Should().Be("qwen2.5-coder:3b");
        cpuChoice.IsQwen.Should().BeTrue();

        // Avec GPU dédié (hasDedicatedGpu: true), qwen3.5:latest gagne
        var gpuChoice = OllamaModelSelector.SelectBestModel(installed, "qwen2.5:7b", autoSelectBestQwen: true, hostRamGb: 15.9, hasDedicatedGpu: true);
        gpuChoice.SelectedModel.Should().Be("qwen3.5:latest");
    }

    [Fact]
    public async Task OllamaAssessor_AutoSelectsBestQwen_SendsOptimizedOptions_WarmsUp_AndUsesSemanticCache()
    {
        var clock = new FakeTimeProvider(TestEvents.BaseTime);
        var chatCalls = 0;
        var warmUpCalls = 0;
        string? lastChatPayload = null;

        var handler = new StubHttpMessageHandler(async (req, ct) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            var body = req.Content is not null ? await req.Content.ReadAsStringAsync(ct) : string.Empty;

            if (path == "/api/tags")
            {
                return StubHttpMessageHandler.JsonResponse("""
                    {
                      "models": [
                        {
                          "name": "qwen2.5-coder:3b",
                          "size": 1984700000,
                          "details": { "family": "qwen2", "parameter_size": "3.1B", "quantization_level": "Q4_K_M" }
                        },
                        {
                          "name": "qwen3:8b",
                          "size": 5200000000,
                          "details": { "family": "qwen3", "parameter_size": "8.2B", "quantization_level": "Q4_K_M" }
                        }
                      ]
                    }
                    """);
            }

            if (path == "/api/generate")
            {
                Interlocked.Increment(ref warmUpCalls);
                return StubHttpMessageHandler.JsonResponse("""{"response":"","done":true}""");
            }

            if (path == "/api/chat")
            {
                Interlocked.Increment(ref chatCalls);
                lastChatPayload = body;
                return StubHttpMessageHandler.JsonResponse(
                    """{"message":{"role":"assistant","content":"{\"score\": 68, \"type\": \"Malware\", \"justification\": \"Exécution PowerShell suspecte confirmée.\", \"confidence\": 0.88}"},"done":true}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        using var http = new HttpClient(handler);
        using var assessor = new OllamaAssessor(
            http,
            new LlmSettings
            {
                Enabled = true,
                Endpoint = "http://localhost:11434",
                Model = "qwen2.5-coder:3b",
                AutoSelectBestQwen = true,
                KeepAlive = "15m",
                ContextWindow = 2048,
                MaxOutputTokens = 140,
                EnableResponseCache = true,
                CacheTtlMinutes = 5,
                WarmUpOnStartup = true
            },
            clock: clock,
            hostRamGbOverride: 16.0);

        // 1. Sélection automatique : qwen3:8b est choisi sur un hôte 16 Go
        var healthy = await assessor.CheckHealthAsync();
        healthy.Should().BeTrue();
        assessor.ActiveModel.Should().Be("qwen3:8b");
        assessor.LastSelection.Should().NotBeNull();
        assessor.LastSelection!.AutoSelected.Should().BeTrue();
        assessor.LastSelection.IsQwen.Should().BeTrue();

        // 2. Préchauffage en mémoire
        var warmed = await assessor.WarmUpAsync();
        warmed.Should().BeTrue();
        warmUpCalls.Should().Be(1);
        assessor.Metrics.WarmedUp.Should().BeTrue();

        // 3. Premier événement ambigu -> appel /api/chat avec options optimisées
        var evt1 = TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, "powershell.exe -enc ABC");
        var ctx1 = new LlmScoringContext(evt1, 52, ThreatType.Malware, "LOLBin", ["PROC-PS-ENC"], [], "Profil normal");
        var r1 = await assessor.AssessAsync(ctx1);

        r1.Should().NotBeNull();
        r1!.Score.Should().Be(68);
        chatCalls.Should().Be(1);
        lastChatPayload.Should().NotBeNull();

        using (var doc = JsonDocument.Parse(lastChatPayload!))
        {
            doc.RootElement.GetProperty("model").GetString().Should().Be("qwen3:8b");
            doc.RootElement.GetProperty("keep_alive").GetString().Should().Be("15m");
            doc.RootElement.GetProperty("think").GetBoolean().Should().BeFalse();
            var opts = doc.RootElement.GetProperty("options");
            opts.GetProperty("temperature").GetInt32().Should().Be(0);
            opts.GetProperty("num_ctx").GetInt32().Should().Be(2048);
            opts.GetProperty("num_predict").GetInt32().Should().Be(140);
        }

        // 4. Rafale : nouvel événement (Event.Id différent) de même signature -> HIT du cache sémantique (< 1 ms, 0 appel HTTP)
        var evt2 = TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, "powershell.exe -enc ABC");
        var ctx2 = new LlmScoringContext(evt2, 53, ThreatType.Malware, "LOLBin", ["PROC-PS-ENC"], [], "Profil normal");
        var r2 = await assessor.AssessAsync(ctx2);

        r2.Should().NotBeNull();
        r2!.Score.Should().Be(68);
        chatCalls.Should().Be(1);
        assessor.Metrics.CacheHits.Should().Be(1);

        // 5. Après expiration du TTL (6 min) -> nouvel appel frais
        clock.Advance(TimeSpan.FromMinutes(6));
        var evt3 = TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, "powershell.exe -enc ABC");
        var ctx3 = new LlmScoringContext(evt3, 52, ThreatType.Malware, "LOLBin", ["PROC-PS-ENC"], [], "Profil normal");
        var r3 = await assessor.AssessAsync(ctx3);

        r3.Should().NotBeNull();
        chatCalls.Should().Be(2);
    }
}
