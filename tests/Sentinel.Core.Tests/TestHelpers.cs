using System.Net;
using System.Text;
using Sentinel.AI;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

internal sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan delta) => _now = _now.Add(delta);
}

internal sealed class FakeLlmAssessor : ILlmAssessor
{
    private readonly Func<LlmScoringContext, CancellationToken, Task<LlmAssessmentResult?>> _handler;
    private long _calls;
    private long _failures;

    public FakeLlmAssessor(
        Func<LlmScoringContext, CancellationToken, Task<LlmAssessmentResult?>> handler,
        bool available = true)
    {
        _handler = handler;
        IsAvailable = available;
    }

    public bool IsAvailable { get; set; }

    public int CallCount => (int)Interlocked.Read(ref _calls);

    public List<LlmScoringContext> ReceivedContexts { get; } = new();

    public LlmMetrics Metrics => new(
        Interlocked.Read(ref _calls),
        Interlocked.Read(ref _calls) - Interlocked.Read(ref _failures),
        Interlocked.Read(ref _failures),
        5.0,
        IsAvailable,
        DateTimeOffset.UtcNow,
        null);

    public async Task<LlmAssessmentResult?> AssessAsync(LlmScoringContext context, CancellationToken ct = default)
    {
        Interlocked.Increment(ref _calls);
        lock (ReceivedContexts) ReceivedContexts.Add(context);
        try
        {
            var res = await _handler(context, ct);
            if (res is null) Interlocked.Increment(ref _failures);
            return res;
        }
        catch
        {
            Interlocked.Increment(ref _failures);
            throw;
        }
    }

    public Task<bool> CheckHealthAsync(CancellationToken ct = default) => Task.FromResult(IsAvailable);

    public Task<float[]?> GetEmbeddingAsync(string text, CancellationToken ct = default) =>
        Task.FromResult<float[]?>(IsAvailable ? [0.1f, 0.2f, 0.3f] : null);
}

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _responder;
    private int _requestCount;

    public StubHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
    {
        _responder = responder;
    }

    public int RequestCount => Volatile.Read(ref _requestCount);

    public List<string> CapturedBodies { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _requestCount);
        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(cancellationToken);
            lock (CapturedBodies) CapturedBodies.Add(body);
        }
        return await _responder(request, cancellationToken);
    }

    public static HttpResponseMessage JsonResponse(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}

internal static class TestEvents
{
    public static readonly DateTimeOffset BaseTime = new(2026, 3, 10, 10, 0, 0, TimeSpan.Zero);

    public static SentinelSettings ActiveSettings(bool llmEnabled = false, bool correlationEnabled = true) => new()
    {
        Mode = OperatingMode.Active,
        Llm = new LlmSettings { Enabled = llmEnabled },
        Correlation = new CorrelationSettings { Enabled = correlationEnabled }
    };

    public static SecurityEvent Make(
        EventCategory category,
        string eventType,
        string subject,
        Dictionary<string, string>? attrs = null,
        DateTimeOffset? ts = null,
        string hostId = "HOST-01",
        string userId = "alice",
        string? hints = null) =>
        SecurityEvent.Create(
            hostId,
            userId,
            category,
            eventType,
            subject,
            attrs ?? new Dictionary<string, string>(),
            hints,
            ts ?? BaseTime);
}
