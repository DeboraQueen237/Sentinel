using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Models;

namespace Sentinel.AI;

/// <summary>
/// Client HTTP léger vers Ollama local (<c>POST /api/chat</c>, <c>GET /api/tags</c>, <c>POST /api/embeddings</c>).
/// Intègre sémaphore de concurrence, cache de disponibilité et backoff exponentiel (5 s → 15 s → 60 s)
/// afin que l'absence d'Ollama n'introduise aucun ralentissement sur le pipeline.
/// </summary>
public sealed class OllamaAssessor : ILlmAssessor, IDisposable
{
    private static readonly TimeSpan[] BackoffSteps =
    [
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(15),
        TimeSpan.FromSeconds(60)
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly ILogger<OllamaAssessor> _logger;
    private readonly TimeProvider _clock;
    private readonly object _stateGate = new();

    private volatile LlmSettings _settings;
    private SemaphoreSlim _concurrencyGate;
    private int _currentMaxConcurrency;

    private bool _isAvailable;
    private int _consecutiveFailures;
    private DateTimeOffset? _lastCheckedAt;
    private DateTimeOffset? _nextRetryAt;

    private long _calls;
    private long _successes;
    private long _failures;
    private long _totalLatencyMicros;
    private bool _disposed;

    public OllamaAssessor(
        HttpClient? httpClient = null,
        LlmSettings? settings = null,
        ILogger<OllamaAssessor>? logger = null,
        TimeProvider? clock = null)
    {
        if (httpClient is null)
        {
            _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }

        _settings = CloneSettings(settings ?? new LlmSettings());
        _logger = logger ?? NullLogger<OllamaAssessor>.Instance;
        _clock = clock ?? TimeProvider.System;
        _currentMaxConcurrency = Math.Max(1, _settings.MaxConcurrency);
        _concurrencyGate = new SemaphoreSlim(_currentMaxConcurrency, _currentMaxConcurrency);
    }

    /// <inheritdoc />
    public bool IsAvailable
    {
        get
        {
            if (!_settings.Enabled) return false;
            lock (_stateGate)
            {
                return _isAvailable;
            }
        }
    }

    /// <inheritdoc />
    public LlmMetrics Metrics
    {
        get
        {
            var calls = Interlocked.Read(ref _calls);
            var successes = Interlocked.Read(ref _successes);
            var failures = Interlocked.Read(ref _failures);
            var totalMicros = Interlocked.Read(ref _totalLatencyMicros);
            var avgMs = calls > 0 ? (totalMicros / 1000.0) / calls : 0.0;

            lock (_stateGate)
            {
                return new LlmMetrics(
                    calls,
                    successes,
                    failures,
                    Math.Round(avgMs, 2),
                    _settings.Enabled && _isAvailable,
                    _lastCheckedAt,
                    _nextRetryAt);
            }
        }
    }

    /// <inheritdoc />
    public void UpdateSettings(LlmSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var copy = CloneSettings(settings);
        var endpointChanged = !string.Equals(_settings.Endpoint, copy.Endpoint, StringComparison.OrdinalIgnoreCase) ||
                              !string.Equals(_settings.Model, copy.Model, StringComparison.OrdinalIgnoreCase);
        _settings = copy;

        var desiredConcurrency = Math.Max(1, copy.MaxConcurrency);
        lock (_stateGate)
        {
            if (desiredConcurrency != _currentMaxConcurrency)
            {
                _currentMaxConcurrency = desiredConcurrency;
                _concurrencyGate = new SemaphoreSlim(desiredConcurrency, desiredConcurrency);
            }

            if (!copy.Enabled)
            {
                _isAvailable = false;
                _nextRetryAt = null;
            }
            else if (endpointChanged)
            {
                // Réinitialise le backoff pour permettre une nouvelle vérification sur le nouvel endpoint/modèle
                _consecutiveFailures = 0;
                _nextRetryAt = null;
            }
        }
    }

    /// <inheritdoc />
    public async Task<bool> CheckHealthAsync(CancellationToken ct = default)
    {
        var cfg = _settings;
        if (!cfg.Enabled)
        {
            lock (_stateGate)
            {
                _isAvailable = false;
                _lastCheckedAt = _clock.GetUtcNow();
            }
            return false;
        }

        var now = _clock.GetUtcNow();
        lock (_stateGate)
        {
            if (!_isAvailable && _nextRetryAt is { } next && now < next)
            {
                return false;
            }
        }

        var url = $"{NormalizeEndpoint(cfg.Endpoint)}/api/tags";
        var timeoutSeconds = Math.Clamp(cfg.TimeoutSeconds, 1, 5);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                RecordUnavailable($"HTTP {(int)response.StatusCode} sur /api/tags");
                return false;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: linkedCts.Token).ConfigureAwait(false);

            var modelFound = HasConfiguredModel(doc.RootElement, cfg.Model);
            if (!modelFound)
            {
                RecordUnavailable($"Modèle Ollama '{cfg.Model}' introuvable dans /api/tags");
                return false;
            }

            MarkAvailable();
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            RecordUnavailable($"Ollama injoignable ({ex.GetType().Name}: {ex.Message})");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ListInstalledModelsAsync(CancellationToken ct = default)
    {
        var cfg = _settings;
        var url = $"{NormalizeEndpoint(cfg.Endpoint)}/api/tags";
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(cfg.TimeoutSeconds, 1, 5)));
        try
        {
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return Array.Empty<string>();
            await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: linkedCts.Token).ConfigureAwait(false);
            if (!doc.RootElement.TryGetProperty("models", out var modelsEl) || modelsEl.ValueKind != JsonValueKind.Array)
                return Array.Empty<string>();

            var list = new List<string>();
            foreach (var item in modelsEl.EnumerateArray())
            {
                var name = TryGetString(item, "name") ?? TryGetString(item, "model");
                if (!string.IsNullOrWhiteSpace(name)) list.Add(name);
            }
            return list;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    /// <inheritdoc />
    public async Task<LlmAssessmentResult?> AssessAsync(LlmScoringContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var cfg = _settings;
        if (!cfg.Enabled) return null;

        // Backoff actif : repli instantané sans appel réseau
        var now = _clock.GetUtcNow();
        lock (_stateGate)
        {
            if (!_isAvailable && _nextRetryAt is { } next && now < next)
            {
                return null;
            }
        }

        var gate = _concurrencyGate;
        var acquired = false;
        var timeout = TimeSpan.FromSeconds(Math.Max(1, cfg.TimeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(timeout);

        var startTs = Stopwatch.GetTimestamp();
        try
        {
            await gate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            acquired = true;
            Interlocked.Increment(ref _calls);

            var payload = new
            {
                model = cfg.Model,
                stream = false,
                format = "json",
                keep_alive = "10m",
                options = new { temperature = 0 },
                messages = new object[]
                {
                    new { role = "system", content = PromptBuilder.SystemPrompt },
                    new { role = "user", content = PromptBuilder.BuildUserPrompt(context) }
                }
            };

            var url = $"{NormalizeEndpoint(cfg.Endpoint)}/api/chat";
            using var content = new StringContent(
                JsonSerializer.Serialize(payload, SerializerOptions),
                Encoding.UTF8,
                "application/json");

            using var response = await _http.PostAsync(url, content, linkedCts.Token).ConfigureAwait(false);
            var elapsedMs = Stopwatch.GetElapsedTime(startTs).TotalMilliseconds;
            RecordLatency(elapsedMs);

            if (!response.IsSuccessStatusCode)
            {
                Interlocked.Increment(ref _failures);
                RecordUnavailable($"HTTP {(int)response.StatusCode} sur /api/chat");
                return null;
            }

            var rawBody = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);
            var assistantText = ExtractChatMessageContent(rawBody);
            var validated = LlmResponseValidator.Validate(assistantText, Math.Round(elapsedMs, 2));

            if (validated is null)
            {
                Interlocked.Increment(ref _failures);
                _logger.LogWarning("Réponse JSON Ollama invalide pour l'événement {EventId}, repli règles.", context.Event.Id);
                return null;
            }

            MarkAvailable();
            Interlocked.Increment(ref _successes);
            return validated;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var elapsedMs = Stopwatch.GetElapsedTime(startTs).TotalMilliseconds;
            RecordLatency(elapsedMs);
            Interlocked.Increment(ref _failures);
            RecordUnavailable($"Échec appel Ollama /api/chat ({ex.GetType().Name}: {ex.Message})");
            return null;
        }
        finally
        {
            if (acquired)
            {
                try { gate.Release(); } catch (ObjectDisposedException) { }
            }
        }
    }

    /// <inheritdoc />
    public async Task<float[]?> GetEmbeddingAsync(string text, CancellationToken ct = default)
    {
        var cfg = _settings;
        if (!cfg.Enabled || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(cfg.EmbeddingModel))
        {
            return null;
        }

        var now = _clock.GetUtcNow();
        lock (_stateGate)
        {
            if (!_isAvailable && _nextRetryAt is { } next && now < next)
            {
                return null;
            }
        }

        var gate = _concurrencyGate;
        var acquired = false;
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, cfg.TimeoutSeconds)));

        try
        {
            await gate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            acquired = true;

            var url = $"{NormalizeEndpoint(cfg.Endpoint)}/api/embeddings";
            var payload = new
            {
                model = cfg.EmbeddingModel,
                prompt = PromptBuilder.SanitizeUntrusted(text, 2000)
            };

            using var response = await _http.PostAsJsonAsync(url, payload, SerializerOptions, linkedCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: linkedCts.Token).ConfigureAwait(false);

            if (!doc.RootElement.TryGetProperty("embedding", out var embEl) ||
                embEl.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var vector = new float[embEl.GetArrayLength()];
            var i = 0;
            foreach (var item in embEl.EnumerateArray())
            {
                vector[i++] = item.GetSingle();
            }
            return vector.Length > 0 ? vector : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Embedding Ollama indisponible.");
            return null;
        }
        finally
        {
            if (acquired)
            {
                try { gate.Release(); } catch (ObjectDisposedException) { }
            }
        }
    }

    internal static bool HasConfiguredModel(JsonElement tagsRoot, string configuredModel)
    {
        if (string.IsNullOrWhiteSpace(configuredModel)) return false;
        if (!tagsRoot.TryGetProperty("models", out var modelsEl) || modelsEl.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var target = configuredModel.Trim();
        var targetHasTag = target.Contains(':');
        var targetBase = targetHasTag ? target[..target.IndexOf(':')] : target;

        foreach (var item in modelsEl.EnumerateArray())
        {
            var name = TryGetString(item, "name") ?? TryGetString(item, "model");
            if (string.IsNullOrWhiteSpace(name)) continue;

            if (name.Equals(target, StringComparison.OrdinalIgnoreCase)) return true;

            if (targetHasTag)
            {
                // Préfixe exact avec tag (ex. "qwen2.5:7b" correspond à "qwen2.5:7b-instruct")
                if (name.StartsWith(target, StringComparison.OrdinalIgnoreCase)) return true;
                // Cas ":latest" implicite
                if (target.EndsWith(":latest", StringComparison.OrdinalIgnoreCase) &&
                    name.Equals(targetBase, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else
            {
                // Modèle sans tag (ex. "qwen2.5" correspond à "qwen2.5:7b" ou "qwen2.5:latest")
                if (name.StartsWith(targetBase + ":", StringComparison.OrdinalIgnoreCase)) return true;
            }
        }

        return false;
    }

    private static string? ExtractChatMessageContent(string rawBody)
    {
        if (string.IsNullOrWhiteSpace(rawBody)) return null;
        try
        {
            using var doc = JsonDocument.Parse(rawBody);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;

            if (doc.RootElement.TryGetProperty("message", out var msg) &&
                msg.ValueKind == JsonValueKind.Object &&
                msg.TryGetProperty("content", out var content) &&
                content.ValueKind == JsonValueKind.String)
            {
                return content.GetString();
            }

            // Compatibilité éventuelle avec /api/generate ("response")
            if (doc.RootElement.TryGetProperty("response", out var resp) &&
                resp.ValueKind == JsonValueKind.String)
            {
                return resp.GetString();
            }
        }
        catch (JsonException)
        {
            return null;
        }
        return null;
    }

    private static string? TryGetString(JsonElement obj, string prop) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.TryGetProperty(prop, out var el) &&
        el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;

    private void MarkAvailable()
    {
        lock (_stateGate)
        {
            _isAvailable = true;
            _consecutiveFailures = 0;
            _lastCheckedAt = _clock.GetUtcNow();
            _nextRetryAt = null;
        }
    }

    private void RecordUnavailable(string reason)
    {
        TimeSpan delay;
        lock (_stateGate)
        {
            var now = _clock.GetUtcNow();
            _isAvailable = false;
            _lastCheckedAt = now;
            var stepIndex = Math.Min(_consecutiveFailures, BackoffSteps.Length - 1);
            delay = BackoffSteps[stepIndex];
            _consecutiveFailures++;
            _nextRetryAt = now + delay;
        }

        _logger.LogDebug("Ollama indisponible ({Reason}). Prochaine tentative dans {BackoffSeconds} s.", reason, delay.TotalSeconds);
    }

    private void RecordLatency(double elapsedMs)
    {
        var micros = (long)Math.Max(0, Math.Round(elapsedMs * 1000.0));
        Interlocked.Add(ref _totalLatencyMicros, micros);
    }

    private static string NormalizeEndpoint(string? endpoint)
    {
        var trimmed = string.IsNullOrWhiteSpace(endpoint) ? "http://localhost:11434" : endpoint.Trim();
        return trimmed.TrimEnd('/');
    }

    private static LlmSettings CloneSettings(LlmSettings s) => new()
    {
        Enabled = s.Enabled,
        Endpoint = s.Endpoint,
        Model = s.Model,
        EmbeddingModel = s.EmbeddingModel,
        TimeoutSeconds = s.TimeoutSeconds,
        AmbiguityLow = s.AmbiguityLow,
        AmbiguityHigh = s.AmbiguityHigh,
        MinConfidence = s.MinConfidence,
        MaxConcurrency = s.MaxConcurrency
    };

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
        _concurrencyGate.Dispose();
    }
}
