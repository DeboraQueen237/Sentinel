using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;

namespace Sentinel.Server.Tests;

public sealed class AlertNotificationTests
{
    [Fact]
    public void NotificationSecretStore_EncryptsWithDpapi_AndNeverStoresPlaintext()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), "sentinel-secret-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpDir);
        try
        {
            var secretFile = Path.Combine(tmpDir, "notif.dpapi");
            var cfg = new ConfigurationBuilder().Build();
            var store = new NotificationSecretStore(cfg, NullLogger<NotificationSecretStore>.Instance, secretFile);

            var status = store.Update(new NotificationSecretsRequest(
                SmtpPassword: "SmtpSuperSecret!99",
                WhatsAppAccessToken: "EAA_WHATSAPP_TOKEN_XYZ",
                WebhookSecret: "hmac-secret-key-42"));

            status.HasSmtpPassword.Should().BeTrue();
            status.HasWhatsAppToken.Should().BeTrue();
            status.HasWebhookSecret.Should().BeTrue();

            var rawOnDisk = File.ReadAllText(secretFile);
            rawOnDisk.Should().NotContain("SmtpSuperSecret!99");
            rawOnDisk.Should().NotContain("EAA_WHATSAPP_TOKEN_XYZ");
            rawOnDisk.Should().NotContain("hmac-secret-key-42");

            var loaded = store.Load();
            loaded.SmtpPassword.Should().Be("SmtpSuperSecret!99");
            loaded.WhatsAppAccessToken.Should().Be("EAA_WHATSAPP_TOKEN_XYZ");
            loaded.WebhookSecret.Should().Be("hmac-secret-key-42");

            var cleared = store.Update(new NotificationSecretsRequest(ClearWhatsAppToken: true));
            cleared.HasWhatsAppToken.Should().BeFalse();
            cleared.HasSmtpPassword.Should().BeTrue();
        }
        finally
        {
            try { Directory.Delete(tmpDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task AlertNotificationService_RoutesByCriticality_ForAlertsAndCorrelatedClusters()
    {
        var smtp = new RecordingSmtpTransport();
        var httpCapture = new RecordingHttpHandler();
        var (svc, tmpDir) = CreateService(smtp, httpCapture);

        try
        {
            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                CooldownMinutes = 5,
                NotifyOnCorrelatedCluster = true,
                Email = new EmailNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.High,
                    SmtpHost = "smtp.local",
                    FromAddress = "sentinel@local.test",
                    Recipients = ["admin@local.test"]
                },
                WhatsApp = new WhatsAppNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.Critical,
                    Provider = "MetaCloud",
                    PhoneNumberId = "100200300",
                    Recipients = ["+237690000001"]
                },
                Webhook = new WebhookNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.Moderate,
                    Format = "GenericJson",
                    Url = "https://soc.example.test/webhook"
                }
            });

            // 1. Alerte Modérée -> uniquement Webhook (MinLevel=Moderate)
            svc.EnqueueAlert(MakeAlert(ThreatLevel.Moderate, 60));
            await svc.DrainAsync();
            smtp.Sent.Should().BeEmpty();
            httpCapture.Requests.Should().HaveCount(1);
            httpCapture.Requests[0].Uri.Should().Contain("soc.example.test/webhook");

            // 2. Alerte Élevée -> Email + Webhook (PAS WhatsApp qui exige Critical)
            svc.EnqueueAlert(MakeAlert(ThreatLevel.High, 82));
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(1);
            httpCapture.Requests.Should().HaveCount(2);
            httpCapture.Requests.Should().NotContain(r => r.Uri.Contains("graph.facebook.com"));

            // 3. Alerte Critique -> Email + WhatsApp + Webhook
            svc.EnqueueAlert(MakeAlert(ThreatLevel.Critical, 95));
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(2);
            httpCapture.Requests.Should().Contain(r => r.Uri.Contains("graph.facebook.com/v21.0/100200300/messages"));

            // 4. Cluster corrélé Critique -> déclenche tous les canaux activés
            var cluster = new ClusterDto(
                Id: Guid.NewGuid(),
                HostId: "PC-COMPTA-01",
                FirstSeen: DateTimeOffset.UtcNow.AddMinutes(-2),
                LastSeen: DateTimeOffset.UtcNow,
                Score: 93,
                MaxEventScore: 80,
                Level: ThreatLevel.Critical,
                DominantType: ThreatType.Ransomware,
                EventCount: 4,
                Escalated: true,
                ChainId: "CHAIN-RANSOM",
                ChainName: "Rançongiciel par canari",
                ChainStepsMatched: 3,
                ChainTotalSteps: 3,
                ContextKeys: ["canary:Documents", "proc:encryptor.exe"],
                MitreTechniques: ["T1486", "T1059.001"],
                Justification: "Fichier canari modifié et pics d'entropie.");

            svc.EnqueueCluster(cluster);
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(3);
            smtp.Sent[^1].Subject.Should().Contain("CRITIQUE");
            smtp.Sent[^1].PlainBody.Should().Contain("Rançongiciel par canari");
            httpCapture.Requests.Count(r => r.Uri.Contains("graph.facebook.com")).Should().Be(2);

            var status = svc.GetStatus();
            status.TotalSent.Should().Be(9); // 1 + 2 + 3 + 3
            status.TotalFailed.Should().Be(0);
            status.RecentDeliveries.Should().HaveCount(9);
        }
        finally
        {
            CleanupDir(tmpDir);
        }
    }

    [Fact]
    public async Task AlertNotificationService_CooldownSuppressesDuplicates_AndEscalationBypassesCooldown()
    {
        var smtp = new RecordingSmtpTransport();
        var httpCapture = new RecordingHttpHandler();
        var (svc, tmpDir) = CreateService(smtp, httpCapture);

        try
        {
            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                CooldownMinutes = 10,
                Email = new EmailNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.High,
                    SmtpHost = "smtp.local",
                    FromAddress = "sentinel@local.test",
                    Recipients = ["admin@local.test"]
                }
            });

            var alertId = Guid.NewGuid();
            var highAlert = MakeAlert(ThreatLevel.High, 80, id: alertId);

            // Premier envoi : envoyé
            svc.EnqueueAlert(highAlert);
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(1);

            // Doublon identique dans les 10 min : bloqué par anti-spam cooldown
            svc.EnqueueAlert(highAlert);
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(1);
            svc.GetStatus().SuppressedByCooldown.Should().Be(1);

            // Escalade High -> Critical sur la même alerte : contourne immédiatement le cooldown !
            var escalated = highAlert with { Level = ThreatLevel.Critical, Score = 96 };
            svc.EnqueueAlert(escalated, isEscalation: true);
            await svc.DrainAsync();
            smtp.Sent.Should().HaveCount(2);
            smtp.Sent[^1].Subject.Should().Contain("CRITIQUE");
        }
        finally
        {
            CleanupDir(tmpDir);
        }
    }

    [Fact]
    public async Task AlertNotificationService_FormatsWhatsAppMeta_Twilio_WebhookHmac_Slack_Teams_AndTelegram()
    {
        var smtp = new RecordingSmtpTransport();
        var httpCapture = new RecordingHttpHandler();
        var (svc, tmpDir) = CreateService(smtp, httpCapture);

        try
        {
            // 1. WhatsApp Meta Cloud + GenericJson avec signature HMAC-SHA256
            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                WhatsApp = new WhatsAppNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.High,
                    Provider = "MetaCloud",
                    PhoneNumberId = "99887766",
                    ApiVersion = "v21.0",
                    Recipients = ["+237 699-11-22-33"]
                },
                Webhook = new WebhookNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.High,
                    Format = "GenericJson",
                    Url = "https://hooks.soc.local/events"
                }
            });

            var waTest = await svc.SendTestAsync("whatsapp");
            waTest.Success.Should().BeTrue();
            var metaReq = httpCapture.Requests.Last();
            metaReq.Uri.Should().Be("https://graph.facebook.com/v21.0/99887766/messages");
            metaReq.Authorization.Should().Be("Bearer WA_TEST_TOKEN_123");
            using (var doc = JsonDocument.Parse(metaReq.Body))
            {
                doc.RootElement.GetProperty("messaging_product").GetString().Should().Be("whatsapp");
                doc.RootElement.GetProperty("to").GetString().Should().Be("237699112233");
                doc.RootElement.GetProperty("text").GetProperty("body").GetString().Should().Contain("SENTINEL SOC");
            }

            var whTest = await svc.SendTestAsync("webhook");
            whTest.Success.Should().BeTrue();
            var whReq = httpCapture.Requests.Last();
            whReq.SentinelSignature.Should().NotBeNullOrEmpty();
            var expectedHmac = "sha256=" + AlertNotificationService.ComputeHmacSha256Hex("WEBHOOK_SECRET_456", whReq.Body);
            whReq.SentinelSignature.Should().Be(expectedHmac);

            // 2. WhatsApp Twilio
            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                WhatsApp = new WhatsAppNotificationSettings
                {
                    Enabled = true,
                    MinLevel = ThreatLevel.High,
                    Provider = "Twilio",
                    AccountSid = "AC1234567890",
                    FromNumber = "+14155238886",
                    Recipients = ["+237699112233"]
                }
            });
            var twilioRes = await svc.SendTestAsync("whatsapp");
            twilioRes.Success.Should().BeTrue();
            var twilioReq = httpCapture.Requests.Last();
            twilioReq.Uri.Should().Be("https://api.twilio.com/2010-04-01/Accounts/AC1234567890/Messages.json");
            twilioReq.Authorization.Should().StartWith("Basic ");
            twilioReq.Body.Should().Contain("whatsapp%3A%2B237699112233");

            // 3. Teams MessageCard & Telegram Bot API
            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                Webhook = new WebhookNotificationSettings
                {
                    Enabled = true,
                    Format = "Teams",
                    Url = "https://outlook.office.com/webhook/test"
                }
            });
            (await svc.SendTestAsync("webhook")).Success.Should().BeTrue();
            httpCapture.Requests.Last().Body.Should().Contain("MessageCard");

            svc.UpdateSettings(new NotificationSettings
            {
                Enabled = true,
                Webhook = new WebhookNotificationSettings
                {
                    Enabled = true,
                    Format = "Telegram",
                    TelegramChatId = "-100999888"
                }
            });
            (await svc.SendTestAsync("webhook")).Success.Should().BeTrue();
            var tgReq = httpCapture.Requests.Last();
            tgReq.Uri.Should().Contain("api.telegram.org/botWEBHOOK_SECRET_456/sendMessage");
            tgReq.Body.Should().Contain("-100999888");
        }
        finally
        {
            CleanupDir(tmpDir);
        }
    }

    [Fact]
    public async Task ApiEndpoints_LlmAndNotifications_WorkEndToEnd_WithZeroSecretsInSqlite()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();

        // 1. Statut LLM & auto-sélection Qwen
        var llmResp = await client.GetAsync(ApiRoutes.LlmStatus);
        llmResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var llmStatus = await llmResp.Content.ReadFromJsonAsync<LlmStatusDto>(SentinelJson.Options);
        llmStatus.Should().NotBeNull();
        llmStatus!.AutoSelectBestQwen.Should().BeTrue();
        llmStatus.ContextWindow.Should().Be(2048);
        llmStatus.MaxOutputTokens.Should().Be(160);

        var autoSelectResp = await client.PostAsync(ApiRoutes.LlmSelectBest, null);
        autoSelectResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // 2. Enregistrement des secrets DPAPI via PUT /api/notifications/secrets
        var secResp = await client.PutAsJsonAsync(
            ApiRoutes.NotificationSecrets,
            new NotificationSecretsRequest(
                SmtpPassword: "SECRET_SMTP_DO_NOT_LEAK",
                WhatsAppAccessToken: "SECRET_WA_DO_NOT_LEAK",
                WebhookSecret: "SECRET_WH_DO_NOT_LEAK"),
            SentinelJson.Options);
        secResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var secStatus = await secResp.Content.ReadFromJsonAsync<NotificationSecretsStatusDto>(SentinelJson.Options);
        secStatus!.HasSmtpPassword.Should().BeTrue();
        secStatus.HasWhatsAppToken.Should().BeTrue();
        secStatus.HasWebhookSecret.Should().BeTrue();

        // 3. Sauvegarde des paramètres de notification via PUT /api/settings
        var currentSettings = (await client.GetFromJsonAsync<SentinelSettings>(ApiRoutes.Settings, SentinelJson.Options))!;
        currentSettings.Notifications.Enabled = true;
        currentSettings.Notifications.CooldownMinutes = 3;
        currentSettings.Notifications.Email.Enabled = true;
        currentSettings.Notifications.Email.MinLevel = ThreatLevel.High;
        currentSettings.Notifications.Email.SmtpHost = "smtp.local.invalid";
        currentSettings.Notifications.Email.FromAddress = "soc@local.test";
        currentSettings.Notifications.Email.Recipients = ["admin@local.test"];
        currentSettings.Notifications.WhatsApp.Enabled = true;
        currentSettings.Notifications.WhatsApp.MinLevel = ThreatLevel.Critical;
        currentSettings.Notifications.WhatsApp.PhoneNumberId = "123456";
        currentSettings.Notifications.WhatsApp.Recipients = ["+237690000001"];

        var saveResp = await client.PutAsJsonAsync(ApiRoutes.Settings, currentSettings, SentinelJson.Options);
        saveResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // 4. Vérifier GET /api/notifications/status
        var notifStatus = await client.GetFromJsonAsync<NotificationStatusDto>(ApiRoutes.NotificationStatus, SentinelJson.Options);
        notifStatus.Should().NotBeNull();
        notifStatus!.GlobalEnabled.Should().BeTrue();
        notifStatus.EmailEnabled.Should().BeTrue();
        notifStatus.WhatsAppEnabled.Should().BeTrue();
        notifStatus.WhatsAppMinLevel.Should().Be(ThreatLevel.Critical);
        notifStatus.Secrets.HasWhatsAppToken.Should().BeTrue();

        // 5. Invariant sécurité : aucun secret en clair dans la base SQLite (Settings ni AuditEntries)
        using var scope = factory.Services.CreateScope();
        var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
        await using var db = await dbFactory.CreateDbContextAsync();
        var rawSettingsJson = (await db.Settings.AsNoTracking().FirstAsync()).SettingsJson;
        rawSettingsJson.Should().NotContain("SECRET_SMTP_DO_NOT_LEAK");
        rawSettingsJson.Should().NotContain("SECRET_WA_DO_NOT_LEAK");
        rawSettingsJson.Should().NotContain("SECRET_WH_DO_NOT_LEAK");

        var auditTexts = await db.AuditEntries.AsNoTracking().Select(a => a.Details).ToListAsync();
        auditTexts.Should().NotContain(d => d.Contains("SECRET_SMTP_DO_NOT_LEAK") || d.Contains("SECRET_WA_DO_NOT_LEAK"));
    }

    private static (AlertNotificationService Service, string TempDir) CreateService(
        RecordingSmtpTransport smtp,
        RecordingHttpHandler httpHandler)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), "sentinel-notif-svc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpDir);
        var secretStore = new NotificationSecretStore(
            new ConfigurationBuilder().Build(),
            NullLogger<NotificationSecretStore>.Instance,
            Path.Combine(tmpDir, "secrets.dpapi"));
        secretStore.Update(new NotificationSecretsRequest(
            SmtpPassword: "SMTP_TEST_PASSWORD",
            WhatsAppAccessToken: "WA_TEST_TOKEN_123",
            WebhookSecret: "WEBHOOK_SECRET_456"));

        var svc = new AlertNotificationService(
            new SingleHandlerHttpClientFactory(httpHandler),
            smtp,
            secretStore,
            NullLogger<AlertNotificationService>.Instance,
            retryDelays: [TimeSpan.Zero]);

        return (svc, tmpDir);
    }

    private static AlertDto MakeAlert(ThreatLevel level, int score, Guid? id = null) => new(
        Id: id ?? Guid.NewGuid(),
        CreatedAt: DateTimeOffset.UtcNow,
        UpdatedAt: DateTimeOffset.UtcNow,
        HostId: "PC-FINANCE-01",
        UserId: "alice",
        Title: $"Menace {level} détectée",
        Summary: "Exécution suspecte détectée par corrélation multi-moteurs.",
        Score: score,
        Level: level,
        ThreatType: ThreatType.Malware,
        Status: AlertStatus.Open,
        ClusterId: null,
        EventCount: 2,
        PendingActions: 1,
        RequiresDecision: true,
        MitreTechniques: ["T1059.001"]);

    private static void CleanupDir(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
    }

    private sealed record CapturedEmail(string Subject, string PlainBody, string HtmlBody, string? Password);

    private sealed class RecordingSmtpTransport : ISmtpMailTransport
    {
        public List<CapturedEmail> Sent { get; } = new();

        public Task SendAsync(
            EmailNotificationSettings config,
            string? password,
            string subject,
            string plainBody,
            string htmlBody,
            CancellationToken ct = default)
        {
            Sent.Add(new CapturedEmail(subject, plainBody, htmlBody, password));
            return Task.CompletedTask;
        }
    }

    private sealed record CapturedHttp(string Uri, string? Authorization, string? SentinelSignature, string Body);

    private sealed class RecordingHttpHandler : HttpMessageHandler
    {
        public List<CapturedHttp> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is not null
                ? await request.Content.ReadAsStringAsync(cancellationToken)
                : string.Empty;
            var auth = request.Headers.Authorization?.ToString();
            request.Headers.TryGetValues("X-Sentinel-Signature", out var sigValues);
            Requests.Add(new CapturedHttp(request.RequestUri?.ToString() ?? string.Empty, auth, sigValues?.FirstOrDefault(), body));

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"ok":true}""", Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class SingleHandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
