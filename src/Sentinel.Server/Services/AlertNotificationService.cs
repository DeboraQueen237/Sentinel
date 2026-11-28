using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Sentinel.Server.Hubs;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Services;

/// <summary>Contrat d'envoi asynchrone des notifications administrateur par niveau de criticité.</summary>
public interface IAlertNotificationDispatcher
{
    void UpdateSettings(NotificationSettings settings);
    void EnqueueAlert(AlertDto alert, bool isEscalation = false);
    void EnqueueCluster(ClusterDto cluster);
    Task<NotificationDeliveryDto> SendTestAsync(string channel, CancellationToken ct = default);
    NotificationStatusDto GetStatus();
    IReadOnlyList<InAppNotificationDto> GetInbox();
    int MarkAllRead();
    Task DrainAsync(CancellationToken ct = default);
}

/// <summary>Transport SMTP injectable pour envoi d'e-mails d'alerte (testable sans serveur SMTP externe).</summary>
public interface ISmtpMailTransport
{
    Task SendAsync(
        EmailNotificationSettings config,
        string? password,
        string subject,
        string plainBody,
        string htmlBody,
        CancellationToken ct = default);
}

/// <summary>Implémentation SMTP native .NET avec TLS/STARTTLS.</summary>
public sealed class SystemSmtpMailTransport : ISmtpMailTransport
{
    public async Task SendAsync(
        EmailNotificationSettings config,
        string? password,
        string subject,
        string plainBody,
        string htmlBody,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(config);

        using var message = new MailMessage
        {
            From = new MailAddress(config.FromAddress.Trim(), string.IsNullOrWhiteSpace(config.FromName) ? "SENTINEL SOC" : config.FromName.Trim()),
            Subject = subject,
            SubjectEncoding = Encoding.UTF8,
            Body = plainBody,
            BodyEncoding = Encoding.UTF8,
            IsBodyHtml = false
        };

        foreach (var recipient in config.Recipients)
        {
            var trimmed = recipient?.Trim();
            if (!string.IsNullOrWhiteSpace(trimmed))
            {
                message.To.Add(trimmed);
            }
        }

        if (message.To.Count == 0)
        {
            throw new InvalidOperationException("Aucun destinataire e-mail configuré.");
        }

        message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(plainBody, Encoding.UTF8, MediaTypeNames.Text.Plain));
        message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(htmlBody, Encoding.UTF8, MediaTypeNames.Text.Html));

        using var client = new SmtpClient(config.SmtpHost.Trim(), Math.Clamp(config.SmtpPort, 1, 65535))
        {
            EnableSsl = config.UseStartTls,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 12_000
        };

        if (!string.IsNullOrWhiteSpace(config.Username))
        {
            client.UseDefaultCredentials = false;
            client.Credentials = new NetworkCredential(config.Username.Trim(), password ?? string.Empty);
        }

        await client.SendMailAsync(message, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Service d'arrière-plan gérant les notifications administrateur multi-canaux :
/// - Centre de notifications temps réel In-App (SignalR + cloche console, actif par défaut)
/// - Email SMTP TLS/STARTTLS
/// - SMS (Twilio SMS ou passerelle HTTP régionale/opérateur)
/// - WhatsApp (Meta Cloud API v21.0 ou Twilio WhatsApp)
/// - Webhook / Slack / Microsoft Teams / Discord / Telegram
/// Strictement respectueux de la vie privée (métadonnées uniquement, secrets chiffrés DPAPI).
/// </summary>
public sealed class AlertNotificationService : BackgroundService, IAlertNotificationDispatcher
{
    public const string HttpClientName = "SentinelNotifications";
    private const int MaxQueueCapacity = 256;
    private const int MaxDeliveryHistory = 60;
    private const int MaxInAppInbox = 80;

    private sealed record NotificationEnvelope(
        string TriggerKind,
        ThreatLevel Level,
        int Score,
        ThreatType ThreatType,
        string HostId,
        string UserId,
        string Title,
        string Summary,
        IReadOnlyList<string> MitreTechniques,
        string? ChainName,
        int EventCount,
        string ReferenceId,
        string? TargetUrl,
        DateTimeOffset Timestamp,
        bool ForceBypassCooldown);

    private sealed record CooldownRecord(DateTimeOffset SentAt, ThreatLevel Level);

    private readonly IHttpClientFactory _httpFactory;
    private readonly ISmtpMailTransport _smtpTransport;
    private readonly NotificationSecretStore _secretStore;
    private readonly HashChainWriter? _auditWriter;
    private readonly LiveBroadcaster? _broadcaster;
    private readonly TimeProvider _clock;
    private readonly ILogger<AlertNotificationService> _logger;
    private readonly TimeSpan[] _retryDelays;

    private readonly Channel<NotificationEnvelope> _queue;
    private readonly object _stateGate = new();
    private readonly Dictionary<string, CooldownRecord> _cooldowns = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<NotificationDeliveryDto> _history = new();
    private readonly LinkedList<InAppNotificationDto> _inbox = new();

    private volatile NotificationSettings _settings = new();
    private int _pendingWorkCount;
    private long _totalSent;
    private long _totalFailed;
    private long _suppressedByCooldown;

    public AlertNotificationService(
        IHttpClientFactory httpFactory,
        ISmtpMailTransport smtpTransport,
        NotificationSecretStore secretStore,
        ILogger<AlertNotificationService> logger,
        HashChainWriter? auditWriter = null,
        LiveBroadcaster? broadcaster = null,
        TimeProvider? clock = null,
        TimeSpan[]? retryDelays = null)
    {
        _httpFactory = httpFactory;
        _smtpTransport = smtpTransport;
        _secretStore = secretStore;
        _logger = logger;
        _auditWriter = auditWriter;
        _broadcaster = broadcaster;
        _clock = clock ?? TimeProvider.System;
        _retryDelays = retryDelays ?? [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(3)];

        _queue = Channel.CreateBounded<NotificationEnvelope>(new BoundedChannelOptions(MaxQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public void UpdateSettings(NotificationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = Clone(settings);
    }

    public void EnqueueAlert(AlertDto alert, bool isEscalation = false)
    {
        ArgumentNullException.ThrowIfNull(alert);
        var cfg = _settings;
        if (!cfg.EnableInApp && (!cfg.Enabled || !HasAnyEnabledExternalChannel(cfg))) return;

        var envelope = new NotificationEnvelope(
            TriggerKind: isEscalation ? "Alerte (Escalade)" : "Alerte",
            Level: alert.Level,
            Score: alert.Score,
            ThreatType: alert.ThreatType,
            HostId: Sanitize(alert.HostId, 64),
            UserId: Sanitize(alert.UserId, 64),
            Title: Sanitize(alert.Title, 140),
            Summary: Sanitize(alert.Summary, 320),
            MitreTechniques: alert.MitreTechniques.Take(6).Select(t => Sanitize(t, 24)).ToArray(),
            ChainName: null,
            EventCount: alert.EventCount,
            ReferenceId: alert.ClusterId?.ToString("N") ?? alert.Id.ToString("N"),
            TargetUrl: $"/alerts/{alert.Id}",
            Timestamp: alert.UpdatedAt,
            ForceBypassCooldown: isEscalation);

        EnqueueEnvelope(envelope);
    }

    public void EnqueueCluster(ClusterDto cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);
        var cfg = _settings;
        if (!cfg.NotifyOnCorrelatedCluster) return;
        if (!cfg.EnableInApp && (!cfg.Enabled || !HasAnyEnabledExternalChannel(cfg))) return;

        var title = string.IsNullOrWhiteSpace(cluster.ChainName)
            ? $"Cluster corrélé ({cluster.EventCount} événements — {cluster.DominantType})"
            : $"Chaîne d'attaque corrélée : {cluster.ChainName}";

        var envelope = new NotificationEnvelope(
            TriggerKind: "Cluster corrélé",
            Level: cluster.Level,
            Score: cluster.Score,
            ThreatType: cluster.DominantType,
            HostId: Sanitize(cluster.HostId, 64),
            UserId: "corrélation",
            Title: Sanitize(title, 140),
            Summary: Sanitize(cluster.Justification, 320),
            MitreTechniques: cluster.MitreTechniques.Take(6).Select(t => Sanitize(t, 24)).ToArray(),
            ChainName: string.IsNullOrWhiteSpace(cluster.ChainName) ? null : Sanitize(cluster.ChainName, 80),
            EventCount: cluster.EventCount,
            ReferenceId: cluster.Id.ToString("N"),
            TargetUrl: $"/graph/{cluster.Id}",
            Timestamp: cluster.LastSeen,
            ForceBypassCooldown: cluster.Escalated);

        EnqueueEnvelope(envelope);
    }

    public async Task<NotificationDeliveryDto> SendTestAsync(string channel, CancellationToken ct = default)
    {
        var normalized = NormalizeChannelName(channel);
        var cfg = _settings;
        var envelope = new NotificationEnvelope(
            TriggerKind: "Test",
            Level: ThreatLevel.High,
            Score: 78,
            ThreatType: ThreatType.Anomaly,
            HostId: Environment.MachineName,
            UserId: "admin",
            Title: "Test de notification SENTINEL SOC",
            Summary: "Message de vérification de votre canal d'alerte administrateur. Aucune donnée personnelle ni contenu de fichier n'est transmis.",
            MitreTechniques: ["T1059"],
            ChainName: null,
            EventCount: 1,
            ReferenceId: $"test-{Guid.NewGuid():N}",
            TargetUrl: "/alerts",
            Timestamp: _clock.GetUtcNow(),
            ForceBypassCooldown: true);

        return await DispatchSingleChannelAsync(normalized, envelope, cfg, isTest: true, ct).ConfigureAwait(false);
    }

    public IReadOnlyList<InAppNotificationDto> GetInbox()
    {
        lock (_stateGate)
        {
            return _inbox.ToArray();
        }
    }

    public int MarkAllRead()
    {
        var updated = 0;
        lock (_stateGate)
        {
            for (var node = _inbox.First; node is not null; node = node.Next)
            {
                if (!node.Value.IsRead)
                {
                    node.Value = node.Value with { IsRead = true };
                    updated++;
                }
            }
        }
        return updated;
    }

    public NotificationStatusDto GetStatus()
    {
        var cfg = _settings;
        NotificationDeliveryDto[] deliveries;
        int unreadInApp;
        lock (_stateGate)
        {
            deliveries = _history.ToArray();
            unreadInApp = _inbox.Count(n => !n.IsRead);
        }

        return new NotificationStatusDto(
            GlobalEnabled: cfg.Enabled,
            EmailEnabled: cfg.Email.Enabled,
            EmailMinLevel: cfg.Email.MinLevel,
            WhatsAppEnabled: cfg.WhatsApp.Enabled,
            WhatsAppMinLevel: cfg.WhatsApp.MinLevel,
            WhatsAppProvider: cfg.WhatsApp.Provider,
            WebhookEnabled: cfg.Webhook.Enabled,
            WebhookMinLevel: cfg.Webhook.MinLevel,
            WebhookFormat: cfg.Webhook.Format,
            CooldownMinutes: cfg.CooldownMinutes,
            NotifyOnCorrelatedCluster: cfg.NotifyOnCorrelatedCluster,
            QueuedCount: Math.Max(0, Volatile.Read(ref _pendingWorkCount)),
            TotalSent: Interlocked.Read(ref _totalSent),
            TotalFailed: Interlocked.Read(ref _totalFailed),
            SuppressedByCooldown: Interlocked.Read(ref _suppressedByCooldown),
            Secrets: _secretStore.GetStatus(),
            RecentDeliveries: deliveries,
            InAppEnabled: cfg.EnableInApp,
            InAppMinLevel: cfg.InAppMinLevel,
            UnreadInAppCount: unreadInApp,
            SmsEnabled: cfg.Sms.Enabled,
            SmsMinLevel: cfg.Sms.MinLevel,
            SmsProvider: cfg.Sms.Provider);
    }

    public async Task DrainAsync(CancellationToken ct = default)
    {
        while (_queue.Reader.TryRead(out var env))
        {
            try
            {
                await ProcessEnvelopeAsync(env, ct).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref _pendingWorkCount);
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var env in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await ProcessEnvelopeAsync(env, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Erreur inattendue lors du traitement d'une notification administrateur.");
                }
                finally
                {
                    Interlocked.Decrement(ref _pendingWorkCount);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private void EnqueueEnvelope(NotificationEnvelope envelope)
    {
        Interlocked.Increment(ref _pendingWorkCount);
        if (!_queue.Writer.TryWrite(envelope))
        {
            Interlocked.Decrement(ref _pendingWorkCount);
        }
    }

    private async Task ProcessEnvelopeAsync(NotificationEnvelope env, CancellationToken ct)
    {
        var cfg = _settings;

        // 1. Notification temps réel In-App (cloche console + SignalR) : active indépendamment des canaux externes !
        if (cfg.EnableInApp && env.Level >= cfg.InAppMinLevel && _broadcaster is not null)
        {
            await TryPushInAppWithCooldownAsync(env, cfg, ct).ConfigureAwait(false);
        }

        // 2. Canaux externes opt-in (Email, SMS, WhatsApp, Webhook/Slack/Teams/Telegram)
        if (!cfg.Enabled) return;

        if (cfg.Email.Enabled && env.Level >= cfg.Email.MinLevel)
        {
            await TryDispatchWithCooldownAsync("email", env, cfg, ct).ConfigureAwait(false);
        }

        if (cfg.Sms.Enabled && env.Level >= cfg.Sms.MinLevel)
        {
            await TryDispatchWithCooldownAsync("sms", env, cfg, ct).ConfigureAwait(false);
        }

        if (cfg.WhatsApp.Enabled && env.Level >= cfg.WhatsApp.MinLevel)
        {
            await TryDispatchWithCooldownAsync("whatsapp", env, cfg, ct).ConfigureAwait(false);
        }

        if (cfg.Webhook.Enabled && env.Level >= cfg.Webhook.MinLevel)
        {
            await TryDispatchWithCooldownAsync("webhook", env, cfg, ct).ConfigureAwait(false);
        }
    }

    private async Task TryPushInAppWithCooldownAsync(NotificationEnvelope env, NotificationSettings cfg, CancellationToken ct)
    {
        var cooldownKey = $"inapp|{env.HostId}|{env.ThreatType}|{env.ReferenceId}";
        var now = _clock.GetUtcNow();
        var cooldown = TimeSpan.FromMinutes(Math.Clamp(cfg.CooldownMinutes, 0, 1440));

        lock (_stateGate)
        {
            if (cooldown > TimeSpan.Zero && _cooldowns.TryGetValue(cooldownKey, out var previous))
            {
                if ((now - previous.SentAt) < cooldown && env.Level <= previous.Level)
                {
                    return;
                }
            }
            _cooldowns[cooldownKey] = new CooldownRecord(now, env.Level);
        }

        var item = StoreInAppItem(env, now);
        if (_broadcaster is not null)
        {
            await _broadcaster.NotificationPushedAsync(item, ct).ConfigureAwait(false);
        }
    }

    private InAppNotificationDto StoreInAppItem(NotificationEnvelope env, DateTimeOffset now)
    {
        var dto = new InAppNotificationDto(
            Id: Guid.NewGuid(),
            Timestamp: now,
            Level: env.Level,
            Score: env.Score,
            TriggerKind: env.TriggerKind,
            Title: env.Title,
            Message: env.Summary,
            HostId: env.HostId,
            TargetUrl: env.TargetUrl,
            IsRead: false);

        lock (_stateGate)
        {
            _inbox.AddFirst(dto);
            while (_inbox.Count > MaxInAppInbox)
            {
                _inbox.RemoveLast();
            }
        }

        return dto;
    }

    private async Task TryDispatchWithCooldownAsync(
        string channel,
        NotificationEnvelope env,
        NotificationSettings cfg,
        CancellationToken ct)
    {
        var cooldownKey = $"{channel}|{env.HostId}|{env.ThreatType}|{env.ReferenceId}";
        var now = _clock.GetUtcNow();
        var cooldown = TimeSpan.FromMinutes(Math.Clamp(cfg.CooldownMinutes, 0, 1440));

        if (cooldown > TimeSpan.Zero)
        {
            lock (_stateGate)
            {
                if (_cooldowns.TryGetValue(cooldownKey, out var previous))
                {
                    var isStillInWindow = (now - previous.SentAt) < cooldown;
                    var isSeverityEscalation = env.Level > previous.Level;
                    if (isStillInWindow && !isSeverityEscalation)
                    {
                        Interlocked.Increment(ref _suppressedByCooldown);
                        return;
                    }
                }
            }
        }

        var delivery = await DispatchSingleChannelAsync(channel, env, cfg, isTest: false, ct).ConfigureAwait(false);
        if (delivery.Success)
        {
            lock (_stateGate)
            {
                _cooldowns[cooldownKey] = new CooldownRecord(now, env.Level);
                PruneOldCooldowns(now, cooldown);
            }
        }
    }

    private async Task<NotificationDeliveryDto> DispatchSingleChannelAsync(
        string channel,
        NotificationEnvelope env,
        NotificationSettings cfg,
        bool isTest,
        CancellationToken ct)
    {
        var secrets = _secretStore.Load();
        var sw = Stopwatch.StartNew();
        var attempts = 0;
        var maxAttempts = isTest ? 1 : _retryDelays.Length + 1;
        string? lastError = null;
        var success = false;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            attempts = attempt;
            try
            {
                switch (channel)
                {
                    case "inapp":
                    {
                        var dto = StoreInAppItem(env, _clock.GetUtcNow());
                        if (_broadcaster is not null)
                        {
                            await _broadcaster.NotificationPushedAsync(dto, ct).ConfigureAwait(false);
                        }
                        break;
                    }
                    case "email":
                        await SendEmailAsync(cfg, secrets, env, ct).ConfigureAwait(false);
                        break;
                    case "sms":
                        await SendSmsAsync(cfg, secrets, env, ct).ConfigureAwait(false);
                        break;
                    case "whatsapp":
                        await SendWhatsAppAsync(cfg, secrets, env, ct).ConfigureAwait(false);
                        break;
                    case "webhook":
                        await SendWebhookAsync(cfg, secrets, env, ct).ConfigureAwait(false);
                        break;
                    default:
                        throw new InvalidOperationException($"Canal de notification inconnu : '{channel}'.");
                }

                success = true;
                lastError = null;
                break;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = RedactSecrets(ex.Message, secrets);
                var isTransient = ex is HttpRequestException or TaskCanceledException or SmtpException;
                if (!isTransient || attempt >= maxAttempts)
                {
                    break;
                }

                var delay = _retryDelays[Math.Min(attempt - 1, _retryDelays.Length - 1)];
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }
            }
        }

        sw.Stop();
        var delivery = new NotificationDeliveryDto(
            Id: Guid.NewGuid(),
            Timestamp: _clock.GetUtcNow(),
            Channel: channel,
            TriggerKind: env.TriggerKind,
            Level: env.Level,
            HostId: env.HostId,
            Summary: env.Title,
            Success: success,
            Error: lastError,
            Attempts: attempts,
            ElapsedMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1));

        RecordDelivery(delivery);
        await WriteAuditAsync(delivery, ct).ConfigureAwait(false);
        return delivery;
    }

    private async Task SendEmailAsync(
        NotificationSettings cfg,
        NotificationSecrets secrets,
        NotificationEnvelope env,
        CancellationToken ct)
    {
        var email = cfg.Email;
        if (string.IsNullOrWhiteSpace(email.SmtpHost))
            throw new InvalidOperationException("Serveur SMTP non configuré.");
        if (string.IsNullOrWhiteSpace(email.FromAddress))
            throw new InvalidOperationException("Adresse expéditeur SMTP non configurée.");
        if (email.Recipients.Count == 0 || email.Recipients.All(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException("Aucun destinataire e-mail configuré.");

        var subject = $"[SENTINEL][{LevelLabelFr(env.Level).ToUpperInvariant()}] {env.Title} ({env.HostId})";
        var plain = FormatPlainText(cfg, env);
        var html = FormatEmailHtml(cfg, env);

        await _smtpTransport.SendAsync(email, secrets.SmtpPassword, subject, plain, html, ct).ConfigureAwait(false);
    }

    private async Task SendSmsAsync(
        NotificationSettings cfg,
        NotificationSecrets secrets,
        NotificationEnvelope env,
        CancellationToken ct)
    {
        var sms = cfg.Sms;
        var recipients = sms.Recipients
            .Select(r => r?.Trim())
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r!)
            .ToList();

        if (recipients.Count == 0)
            throw new InvalidOperationException("Aucun numéro destinataire SMS (format E.164 ex. +2376...) configuré.");

        var token = !string.IsNullOrWhiteSpace(secrets.SmsApiToken)
            ? secrets.SmsApiToken
            : secrets.WhatsAppAccessToken;

        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Jeton API SMS / Twilio Auth Token absent du coffre chiffré DPAPI.");

        var smsBody = FormatConciseSmsText(env);
        var client = _httpFactory.CreateClient(HttpClientName);

        if (string.Equals(sms.Provider, "HttpGateway", StringComparison.OrdinalIgnoreCase))
        {
            if (!IsAllowedWebhookUrl(sms.GatewayUrl))
                throw new InvalidOperationException("URL de passerelle SMS invalide (HTTPS requis, ou http://127.0.0.1 en test local).");

            foreach (var to in recipients)
            {
                var payload = new
                {
                    to,
                    from = string.IsNullOrWhiteSpace(sms.FromNumber) ? "SENTINEL" : sms.FromNumber.Trim(),
                    message = smsBody,
                    level = env.Level.ToString(),
                    score = env.Score
                };

                using var req = new HttpRequestMessage(HttpMethod.Post, sms.GatewayUrl.Trim())
                {
                    Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    var err = await ReadSafeErrorSnippetAsync(resp, ct).ConfigureAwait(false);
                    throw new HttpRequestException($"Passerelle SMS HTTP {(int)resp.StatusCode} : {err}");
                }
            }
        }
        else
        {
            // Twilio SMS standard
            if (string.IsNullOrWhiteSpace(sms.AccountSid) || string.IsNullOrWhiteSpace(sms.FromNumber))
                throw new InvalidOperationException("AccountSid et FromNumber Twilio SMS sont requis.");

            var endpoint = $"https://api.twilio.com/2010-04-01/Accounts/{Uri.EscapeDataString(sms.AccountSid.Trim())}/Messages.json";
            var basicToken = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{sms.AccountSid.Trim()}:{token}"));

            foreach (var to in recipients)
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicToken);
                req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["From"] = sms.FromNumber.Trim(),
                    ["To"] = to,
                    ["Body"] = smsBody
                });

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    var err = await ReadSafeErrorSnippetAsync(resp, ct).ConfigureAwait(false);
                    throw new HttpRequestException($"Twilio SMS HTTP {(int)resp.StatusCode} : {err}");
                }
            }
        }
    }

    private async Task SendWhatsAppAsync(
        NotificationSettings cfg,
        NotificationSecrets secrets,
        NotificationEnvelope env,
        CancellationToken ct)
    {
        var wa = cfg.WhatsApp;
        var recipients = wa.Recipients
            .Select(r => r?.Trim())
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r!)
            .ToList();

        if (recipients.Count == 0)
            throw new InvalidOperationException("Aucun numéro destinataire WhatsApp (format E.164) configuré.");

        if (string.IsNullOrWhiteSpace(secrets.WhatsAppAccessToken))
            throw new InvalidOperationException("Jeton d'accès WhatsApp / Twilio Auth Token absent du coffre chiffré DPAPI.");

        var textBody = FormatWhatsAppText(cfg, env);
        var client = _httpFactory.CreateClient(HttpClientName);

        if (string.Equals(wa.Provider, "Twilio", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(wa.AccountSid) || string.IsNullOrWhiteSpace(wa.FromNumber))
                throw new InvalidOperationException("AccountSid et FromNumber Twilio sont requis.");

            var endpoint = $"https://api.twilio.com/2010-04-01/Accounts/{Uri.EscapeDataString(wa.AccountSid.Trim())}/Messages.json";
            var basicToken = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{wa.AccountSid.Trim()}:{secrets.WhatsAppAccessToken}"));
            var fromNormalized = EnsureTwilioWhatsAppPrefix(wa.FromNumber);

            foreach (var to in recipients)
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicToken);
                req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["From"] = fromNormalized,
                    ["To"] = EnsureTwilioWhatsAppPrefix(to),
                    ["Body"] = textBody
                });

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    var body = await ReadSafeErrorSnippetAsync(resp, ct).ConfigureAwait(false);
                    throw new HttpRequestException($"Twilio WhatsApp HTTP {(int)resp.StatusCode} : {body}");
                }
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(wa.PhoneNumberId))
                throw new InvalidOperationException("PhoneNumberId Meta WhatsApp Cloud API requis.");

            var version = string.IsNullOrWhiteSpace(wa.ApiVersion) ? "v21.0" : wa.ApiVersion.Trim();
            var endpoint = $"https://graph.facebook.com/{Uri.EscapeDataString(version)}/{Uri.EscapeDataString(wa.PhoneNumberId.Trim())}/messages";

            foreach (var to in recipients)
            {
                var digits = NormalizeMetaRecipient(to);
                if (string.IsNullOrWhiteSpace(digits)) continue;

                var payload = new
                {
                    messaging_product = "whatsapp",
                    recipient_type = "individual",
                    to = digits,
                    type = "text",
                    text = new
                    {
                        preview_url = false,
                        body = textBody
                    }
                };

                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secrets.WhatsAppAccessToken);
                req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    var body = await ReadSafeErrorSnippetAsync(resp, ct).ConfigureAwait(false);
                    throw new HttpRequestException($"Meta WhatsApp Cloud HTTP {(int)resp.StatusCode} : {body}");
                }
            }
        }
    }

    private async Task SendWebhookAsync(
        NotificationSettings cfg,
        NotificationSecrets secrets,
        NotificationEnvelope env,
        CancellationToken ct)
    {
        var wh = cfg.Webhook;
        var format = string.IsNullOrWhiteSpace(wh.Format) ? "GenericJson" : wh.Format.Trim();
        var client = _httpFactory.CreateClient(HttpClientName);

        if (format.Equals("Telegram", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(secrets.WebhookSecret))
                throw new InvalidOperationException("Jeton Bot Telegram absent du coffre chiffré DPAPI (champ Secret Webhook/Bot).");
            if (string.IsNullOrWhiteSpace(wh.TelegramChatId))
                throw new InvalidOperationException("Identifiant de chat Telegram (TelegramChatId) requis.");

            var tgUrl = $"https://api.telegram.org/bot{secrets.WebhookSecret.Trim()}/sendMessage";
            var tgPayload = new
            {
                chat_id = wh.TelegramChatId.Trim(),
                text = FormatWhatsAppText(cfg, env),
                disable_web_page_preview = true
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, tgUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(tgPayload), Encoding.UTF8, "application/json")
            };
            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                var body = await ReadSafeErrorSnippetAsync(resp, ct).ConfigureAwait(false);
                throw new HttpRequestException($"Telegram Bot API HTTP {(int)resp.StatusCode} : {body}");
            }
            return;
        }

        if (!IsAllowedWebhookUrl(wh.Url))
            throw new InvalidOperationException("URL Webhook invalide (utilisez HTTPS, ou http://127.0.0.1 en test local).");

        string jsonBody;
        if (format.Equals("Slack", StringComparison.OrdinalIgnoreCase))
        {
            jsonBody = JsonSerializer.Serialize(new { text = FormatWhatsAppText(cfg, env) });
        }
        else if (format.Equals("Discord", StringComparison.OrdinalIgnoreCase))
        {
            jsonBody = JsonSerializer.Serialize(new { content = FormatWhatsAppText(cfg, env) });
        }
        else if (format.Equals("Teams", StringComparison.OrdinalIgnoreCase))
        {
            var themeColor = env.Level switch
            {
                ThreatLevel.Critical => "EF4444",
                ThreatLevel.High => "F97316",
                ThreatLevel.Moderate => "F59E0B",
                _ => "06B6D4"
            };
            var teamsCard = new Dictionary<string, object?>
            {
                ["@type"] = "MessageCard",
                ["@context"] = "http://schema.org/extensions",
                ["themeColor"] = themeColor,
                ["summary"] = $"[SENTINEL] {env.Title}",
                ["title"] = $"SENTINEL — {LevelLabelFr(env.Level)} ({env.Score}/100) : {env.Title}",
                ["text"] = FormatPlainText(cfg, env).Replace("\n", "  \n", StringComparison.Ordinal)
            };
            jsonBody = JsonSerializer.Serialize(teamsCard);
        }
        else
        {
            var genericPayload = new
            {
                source = "SENTINEL",
                triggerKind = env.TriggerKind,
                level = env.Level.ToString(),
                score = env.Score,
                threatType = env.ThreatType.ToString(),
                hostId = env.HostId,
                userId = env.UserId,
                title = env.Title,
                summary = env.Summary,
                mitreTechniques = env.MitreTechniques,
                chainName = env.ChainName,
                eventCount = env.EventCount,
                referenceId = env.ReferenceId,
                timestamp = env.Timestamp,
                dashboardUrl = BuildDashboardUrl(cfg)
            };
            jsonBody = SentinelJson.Serialize(genericPayload);
        }

        using var httpReq = new HttpRequestMessage(HttpMethod.Post, wh.Url.Trim())
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
        };

        if (!string.IsNullOrWhiteSpace(secrets.WebhookSecret))
        {
            var sig = ComputeHmacSha256Hex(secrets.WebhookSecret, jsonBody);
            httpReq.Headers.TryAddWithoutValidation("X-Sentinel-Signature", $"sha256={sig}");
        }

        using var httpResp = await client.SendAsync(httpReq, ct).ConfigureAwait(false);
        if (!httpResp.IsSuccessStatusCode)
        {
            var body = await ReadSafeErrorSnippetAsync(httpResp, ct).ConfigureAwait(false);
            throw new HttpRequestException($"Webhook ({format}) HTTP {(int)httpResp.StatusCode} : {body}");
        }
    }

    internal static string ComputeHmacSha256Hex(string secret, string payload)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var dataBytes = Encoding.UTF8.GetBytes(payload);
        var mac = HMACSHA256.HashData(keyBytes, dataBytes);
        return Convert.ToHexString(mac).ToLowerInvariant();
    }

    internal static bool IsAllowedWebhookUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) return true;
        return uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
               (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static string FormatConciseSmsText(NotificationEnvelope env)
    {
        var mitre = env.MitreTechniques.Count > 0 ? $" [{string.Join(",", env.MitreTechniques.Take(2))}]" : string.Empty;
        var msg = $"[SENTINEL {LevelLabelFr(env.Level).ToUpperInvariant()} {env.Score}/100] {env.HostId} - {env.Title}{mitre}. {Sanitize(env.Summary, 110)}";
        return msg.Length <= 280 ? msg : msg[..277] + "...";
    }

    private static string FormatWhatsAppText(NotificationSettings cfg, NotificationEnvelope env)
    {
        var icon = env.Level switch
        {
            ThreatLevel.Critical => "🚨",
            ThreatLevel.High => "⚠️",
            ThreatLevel.Moderate => "🟠",
            _ => "ℹ️"
        };

        var sb = new StringBuilder(512);
        sb.Append(icon).Append(" *SENTINEL SOC — ").Append(LevelLabelFr(env.Level).ToUpperInvariant()).Append("* (").Append(env.Score).AppendLine("/100)");
        sb.Append("• *Déclencheur* : ").AppendLine(env.TriggerKind);
        sb.Append("• *Titre* : ").AppendLine(env.Title);
        sb.Append("• *Poste* : ").Append(env.HostId).Append(" | *Type* : ").AppendLine(env.ThreatType.ToString());
        if (env.MitreTechniques.Count > 0)
            sb.Append("• *MITRE ATT&CK* : ").AppendLine(string.Join(", ", env.MitreTechniques));
        if (!string.IsNullOrWhiteSpace(env.ChainName))
            sb.Append("• *Chaîne* : ").AppendLine(env.ChainName);
        sb.Append("• *Résumé* : ").AppendLine(env.Summary);
        sb.Append("• *Horodatage UTC* : ").AppendLine(env.Timestamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));

        var link = BuildDashboardUrl(cfg);
        if (!string.IsNullOrWhiteSpace(link))
            sb.Append("• *Console locale* : ").Append(link);

        return sb.ToString().Trim();
    }

    private static string FormatPlainText(NotificationSettings cfg, NotificationEnvelope env)
    {
        var sb = new StringBuilder(512);
        sb.AppendLine($"SENTINEL SOC — Alerte {LevelLabelFr(env.Level)} ({env.Score}/100)");
        sb.AppendLine($"Déclencheur : {env.TriggerKind}");
        sb.AppendLine($"Titre       : {env.Title}");
        sb.AppendLine($"Poste       : {env.HostId} (utilisateur : {env.UserId})");
        sb.AppendLine($"Menace      : {env.ThreatType} ({env.EventCount} événement(s))");
        if (env.MitreTechniques.Count > 0)
            sb.AppendLine($"MITRE       : {string.Join(", ", env.MitreTechniques)}");
        if (!string.IsNullOrWhiteSpace(env.ChainName))
            sb.AppendLine($"Chaîne      : {env.ChainName}");
        sb.AppendLine($"Résumé      : {env.Summary}");
        sb.AppendLine($"Horodatage  : {env.Timestamp.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");

        var link = BuildDashboardUrl(cfg);
        if (!string.IsNullOrWhiteSpace(link))
            sb.AppendLine($"Console     : {link}");

        sb.AppendLine();
        sb.AppendLine("Confidentialité SENTINEL : cette notification contient uniquement des métadonnées techniques d'alerte.");
        return sb.ToString();
    }

    private static string FormatEmailHtml(NotificationSettings cfg, NotificationEnvelope env)
    {
        var accent = env.Level switch
        {
            ThreatLevel.Critical => "#ef4444",
            ThreatLevel.High => "#f97316",
            ThreatLevel.Moderate => "#f59e0b",
            _ => "#06b6d4"
        };

        var link = BuildDashboardUrl(cfg);
        var linkBlock = string.IsNullOrWhiteSpace(link)
            ? string.Empty
            : $"<p style=\"margin-top:16px;\"><a href=\"{WebUtility.HtmlEncode(link)}\" style=\"color:#38bdf8;\">Ouvrir la console SENTINEL locale</a></p>";

        var mitreRow = env.MitreTechniques.Count == 0
            ? string.Empty
            : $"<tr><td style=\"padding:6px 10px;color:#94a3b8;\">MITRE ATT&amp;CK</td><td style=\"padding:6px 10px;font-family:Consolas,monospace;\">{WebUtility.HtmlEncode(string.Join(", ", env.MitreTechniques))}</td></tr>";

        return $"""
            <!DOCTYPE html>
            <html lang="fr">
            <body style="margin:0;padding:20px;background:#0f172a;color:#e2e8f0;font-family:Segoe UI,Arial,sans-serif;">
              <div style="max-width:620px;margin:0 auto;background:#1e293b;border-radius:10px;border-top:4px solid {accent};padding:20px;">
                <div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:{accent};font-weight:700;">
                  SENTINEL SOC · {WebUtility.HtmlEncode(env.TriggerKind)} · {WebUtility.HtmlEncode(LevelLabelFr(env.Level))} ({env.Score}/100)
                </div>
                <h2 style="margin:8px 0 14px;font-size:18px;color:#f8fafc;">{WebUtility.HtmlEncode(env.Title)}</h2>
                <table style="width:100%;border-collapse:collapse;font-size:13px;background:#0f172a;border-radius:6px;">
                  <tr><td style="padding:6px 10px;color:#94a3b8;">Poste</td><td style="padding:6px 10px;">{WebUtility.HtmlEncode(env.HostId)}</td></tr>
                  <tr><td style="padding:6px 10px;color:#94a3b8;">Menace</td><td style="padding:6px 10px;">{WebUtility.HtmlEncode(env.ThreatType.ToString())} ({env.EventCount} événement(s))</td></tr>
                  {mitreRow}
                  <tr><td style="padding:6px 10px;color:#94a3b8;">Horodatage UTC</td><td style="padding:6px 10px;">{env.Timestamp.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC</td></tr>
                </table>
                <p style="margin:14px 0 0;line-height:1.5;color:#cbd5e1;">{WebUtility.HtmlEncode(env.Summary)}</p>
                {linkBlock}
                <hr style="border:none;border-top:1px solid #334155;margin:18px 0 10px;" />
                <div style="font-size:11px;color:#94a3b8;">Notification automatique SENTINEL — métadonnées de sécurité uniquement (aucun contenu personnel transmis).</div>
              </div>
            </body>
            </html>
            """;
    }

    private static string? BuildDashboardUrl(NotificationSettings cfg)
    {
        if (!cfg.IncludeDashboardUrl || string.IsNullOrWhiteSpace(cfg.DashboardBaseUrl))
            return null;
        return cfg.DashboardBaseUrl.Trim().TrimEnd('/') + "/alerts";
    }

    private void RecordDelivery(NotificationDeliveryDto delivery)
    {
        if (delivery.Success)
            Interlocked.Increment(ref _totalSent);
        else
            Interlocked.Increment(ref _totalFailed);

        lock (_stateGate)
        {
            _history.AddFirst(delivery);
            while (_history.Count > MaxDeliveryHistory)
            {
                _history.RemoveLast();
            }
        }
    }

    private async Task WriteAuditAsync(NotificationDeliveryDto delivery, CancellationToken ct)
    {
        if (_auditWriter is null) return;
        try
        {
            var action = delivery.Success ? "NotificationSent" : "NotificationFailed";
            var details = delivery.Success
                ? $"Canal={delivery.Channel}, Déclencheur={delivery.TriggerKind}, Criticité={delivery.Level}, Poste={delivery.HostId}, Tentatives={delivery.Attempts}, Latence={delivery.ElapsedMs}ms."
                : $"Canal={delivery.Channel}, Déclencheur={delivery.TriggerKind}, Criticité={delivery.Level}, Poste={delivery.HostId}, Erreur={delivery.Error}.";

            await _auditWriter.WriteAuditAsync(
                "SentinelServer",
                action,
                $"notification:{delivery.Channel}",
                details,
                "127.0.0.1",
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Audit notification ignoré.");
        }
    }

    private void PruneOldCooldowns(DateTimeOffset now, TimeSpan cooldown)
    {
        if (_cooldowns.Count < 128) return;
        var expiry = cooldown + TimeSpan.FromMinutes(10);
        var toRemove = _cooldowns
            .Where(kv => (now - kv.Value.SentAt) > expiry)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var k in toRemove) _cooldowns.Remove(k);
    }

    private static bool HasAnyEnabledExternalChannel(NotificationSettings cfg) =>
        cfg.Email.Enabled || cfg.Sms.Enabled || cfg.WhatsApp.Enabled || cfg.Webhook.Enabled;

    private static string NormalizeChannelName(string? channel) =>
        (channel ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "inapp" or "app" or "console" => "inapp",
            "email" or "smtp" or "mail" => "email",
            "sms" => "sms",
            "whatsapp" or "wa" => "whatsapp",
            "webhook" or "slack" or "teams" or "discord" or "telegram" => "webhook",
            var other => other
        };

    private static string EnsureTwilioWhatsAppPrefix(string raw)
    {
        var trimmed = raw.Trim();
        return trimmed.StartsWith("whatsapp:", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : "whatsapp:" + trimmed;
    }

    private static string NormalizeMetaRecipient(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (var ch in raw)
        {
            if (char.IsDigit(ch)) sb.Append(ch);
        }
        return sb.ToString();
    }

    private static string LevelLabelFr(ThreatLevel level) => level switch
    {
        ThreatLevel.Critical => "Critique",
        ThreatLevel.High => "Élevé",
        ThreatLevel.Moderate => "Modéré",
        ThreatLevel.Low => "Faible",
        _ => "Info"
    };

    private static string Sanitize(string? value, int maxLen)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var sb = new StringBuilder(Math.Min(value.Length, maxLen));
        foreach (var ch in value)
        {
            if (char.IsControl(ch))
            {
                if (sb.Length > 0 && sb[^1] != ' ') sb.Append(' ');
                continue;
            }
            sb.Append(ch);
            if (sb.Length >= maxLen) break;
        }
        return sb.ToString().Trim();
    }

    private static string RedactSecrets(string message, NotificationSecrets secrets)
    {
        var safe = Sanitize(message, 220);
        if (!string.IsNullOrWhiteSpace(secrets.SmtpPassword))
            safe = safe.Replace(secrets.SmtpPassword, "[REDACTED]", StringComparison.Ordinal);
        if (!string.IsNullOrWhiteSpace(secrets.WhatsAppAccessToken))
            safe = safe.Replace(secrets.WhatsAppAccessToken, "[REDACTED]", StringComparison.Ordinal);
        if (!string.IsNullOrWhiteSpace(secrets.WebhookSecret))
            safe = safe.Replace(secrets.WebhookSecret, "[REDACTED]", StringComparison.Ordinal);
        if (!string.IsNullOrWhiteSpace(secrets.SmsApiToken))
            safe = safe.Replace(secrets.SmsApiToken, "[REDACTED]", StringComparison.Ordinal);
        return safe;
    }

    private static async Task<string> ReadSafeErrorSnippetAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return Sanitize(text, 160);
        }
        catch
        {
            return resp.ReasonPhrase ?? "Erreur HTTP";
        }
    }

    private static NotificationSettings Clone(NotificationSettings n) => new()
    {
        Enabled = n.Enabled,
        EnableInApp = n.EnableInApp,
        InAppMinLevel = n.InAppMinLevel,
        EnableSoundOnCritical = n.EnableSoundOnCritical,
        CooldownMinutes = n.CooldownMinutes,
        NotifyOnCorrelatedCluster = n.NotifyOnCorrelatedCluster,
        IncludeDashboardUrl = n.IncludeDashboardUrl,
        DashboardBaseUrl = n.DashboardBaseUrl,
        Email = new EmailNotificationSettings
        {
            Enabled = n.Email.Enabled,
            MinLevel = n.Email.MinLevel,
            SmtpHost = n.Email.SmtpHost,
            SmtpPort = n.Email.SmtpPort,
            UseStartTls = n.Email.UseStartTls,
            Username = n.Email.Username,
            FromAddress = n.Email.FromAddress,
            FromName = n.Email.FromName,
            Recipients = new List<string>(n.Email.Recipients ?? [])
        },
        Sms = new SmsNotificationSettings
        {
            Enabled = n.Sms?.Enabled ?? false,
            MinLevel = n.Sms?.MinLevel ?? ThreatLevel.Critical,
            Provider = n.Sms?.Provider ?? "TwilioSms",
            AccountSid = n.Sms?.AccountSid ?? string.Empty,
            FromNumber = n.Sms?.FromNumber ?? string.Empty,
            GatewayUrl = n.Sms?.GatewayUrl ?? string.Empty,
            Recipients = new List<string>(n.Sms?.Recipients ?? [])
        },
        WhatsApp = new WhatsAppNotificationSettings
        {
            Enabled = n.WhatsApp.Enabled,
            MinLevel = n.WhatsApp.MinLevel,
            Provider = n.WhatsApp.Provider,
            PhoneNumberId = n.WhatsApp.PhoneNumberId,
            AccountSid = n.WhatsApp.AccountSid,
            FromNumber = n.WhatsApp.FromNumber,
            ApiVersion = n.WhatsApp.ApiVersion,
            Recipients = new List<string>(n.WhatsApp.Recipients ?? [])
        },
        Webhook = new WebhookNotificationSettings
        {
            Enabled = n.Webhook.Enabled,
            MinLevel = n.Webhook.MinLevel,
            Format = n.Webhook.Format,
            Url = n.Webhook.Url,
            TelegramChatId = n.Webhook.TelegramChatId
        }
    };
}
