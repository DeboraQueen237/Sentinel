using System.Data.Common;
using System.Net;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting.WindowsServices;
using QuestPDF.Infrastructure;
using Sentinel.Core;
using Sentinel.Server.Configuration;
using Sentinel.Server.Endpoints;
using Sentinel.Server.Grpc;
using Sentinel.Server.Hubs;
using Sentinel.Server.Security;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Security;
using Sentinel.Storage;
using Sentinel.Storage.Services;
using Serilog;

QuestPDF.Settings.License = LicenseType.Community;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = WindowsServiceHelpers.IsWindowsService() ? AppContext.BaseDirectory : null
});

// Journalisation structurée Serilog (console + fichier roulant hors environnement Testing)
builder.Host.UseSerilog((context, services, loggerConfig) =>
{
    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console();

    if (!context.HostingEnvironment.IsEnvironment("Testing"))
    {
        var logFile = Path.Combine(SentinelPaths.Logs, "sentinel-server-.log");
        loggerConfig.WriteTo.File(
            logFile,
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 14,
            shared: true);
    }
});

// Support Service Windows natif (doc §4)
builder.Services.AddWindowsService(o => o.ServiceName = SentinelEndpoints.ServerServiceName);

// Options fortement typées (résolution paresseuse sur la configuration finale)
builder.Services.Configure<SentinelServerOptions>(builder.Configuration.GetSection(SentinelServerOptions.SectionName));

// Configuration Kestrel bi-port évaluée au démarrage (hors Testing où WebApplicationFactory fournit TestServer)
builder.WebHost.ConfigureKestrel((ctx, kestrel) =>
{
    if (ctx.HostingEnvironment.IsEnvironment("Testing"))
        return;

    var opts = new SentinelServerOptions();
    ctx.Configuration.GetSection(SentinelServerOptions.SectionName).Bind(opts);

    // Port 5180 (boucle locale uniquement) : API REST + SignalR /hubs/live
    kestrel.Listen(IPAddress.Loopback, opts.ApiPort, listen =>
    {
        listen.Protocols = HttpProtocols.Http1AndHttp2;
    });

    // Port 5181 (localhost HTTP/2) : canal gRPC agents avec mTLS (doc §4, §11)
    kestrel.ListenLocalhost(opts.GrpcPort, listen =>
    {
        listen.Protocols = HttpProtocols.Http2;

        if (opts.UseMtls)
        {
            SentinelPki.EnsureCertificates();
            var serverCert = SentinelPki.LoadServerCertificate();
            var caCert = SentinelPki.LoadCaCertificate();

            listen.UseHttps(https =>
            {
                https.ServerCertificate = serverCert;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (cert, _, _) => SentinelPki.ValidateIssuedBy(cert, caCert);
            });
        }
    });
});

// CORS configuré paresseusement depuis Sentinel:CorsOrigins
builder.Services.AddCors();
builder.Services.AddOptions<CorsOptions>()
    .Configure<IOptions<SentinelServerOptions>>((cors, serverOpts) =>
    {
        var origins = serverOpts.Value.CorsOrigins is { Length: > 0 }
            ? serverOpts.Value.CorsOrigins
            : ["http://127.0.0.1:5200", "http://localhost:5200"];

        cors.AddDefaultPolicy(policy =>
        {
            policy.WithOrigins(origins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

// Couche Storage résolue paresseusement (permet les surcharges WebApplicationFactory en tests)
var pragmaInterceptor = new ServerSqlitePragmaInterceptor();
builder.Services.AddDbContextFactory<SentinelDbContext>((sp, options) =>
{
    var cs = sp.GetRequiredService<IOptions<SentinelServerOptions>>().Value.ConnectionString;
    var finalCs = string.IsNullOrWhiteSpace(cs)
        ? $"Data Source={SentinelPaths.ServerDatabase}"
        : cs;

    options.UseSqlite(finalCs, sqlite => sqlite.CommandTimeout(30));
    options.AddInterceptors(pragmaInterceptor);
});
builder.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext());
builder.Services.AddSingleton<SentinelDbInitializer>();
builder.Services.AddSingleton<HashChainWriter>();
builder.Services.AddSingleton<IntegrityVerifier>();
builder.Services.AddSingleton<RetentionCleaner>();

// Sérialisation JSON commune (camelCase + JsonStringEnumConverter) sur HTTP et SignalR
builder.Services.ConfigureHttpJsonOptions(o => SentinelJson.Configure(o.SerializerOptions));
builder.Services.AddSignalR()
    .AddJsonProtocol(o => SentinelJson.Configure(o.PayloadSerializerOptions));

// gRPC
builder.Services.AddGrpc(o =>
{
    o.MaxReceiveMessageSize = 16 * 1024 * 1024;
});

// Couche Core (pipeline d'analyse + Ollama)
builder.Services.AddSentinelCore();

// Services métier Sentinel.Server
builder.Services.AddHttpClient(AlertNotificationService.HttpClientName, client =>
{
    client.Timeout = TimeSpan.FromSeconds(12);
});
builder.Services.AddSingleton<NotificationSecretStore>();
builder.Services.AddSingleton<ISmtpMailTransport, SystemSmtpMailTransport>();
builder.Services.AddSingleton<AlertNotificationService>();
builder.Services.AddSingleton<IAlertNotificationDispatcher>(sp => sp.GetRequiredService<AlertNotificationService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<AlertNotificationService>());

builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<AgentCommandHub>();
builder.Services.AddSingleton<LiveBroadcaster>();
builder.Services.AddSingleton<EventIngestionService>();
builder.Services.AddSingleton<DashboardService>();
builder.Services.AddSingleton<GraphBuilderService>();
builder.Services.AddSingleton<EntityProfileService>();
builder.Services.AddSingleton<ReportGeneratorService>();

// Services hébergés : initialisation synchrone puis maintenance périodique
builder.Services.AddHostedService<StartupInitializationService>();
builder.Services.AddHostedService<MaintenanceWorker>();

var app = builder.Build();

app.UseCors();
app.UseMiddleware<BearerSessionMiddleware>();

// gRPC & SignalR
app.MapGrpcService<AgentGatewayService>();
app.MapHub<SentinelLiveHub>(LiveHub.Path);

// Routes REST (ApiRoutes.cs)
app.MapSystemEndpoints();
app.MapAuthEndpoints();
app.MapDashboardEndpoints();
app.MapAlertEndpoints();
app.MapEventEndpoints();
app.MapClusterGraphEndpoints();
app.MapActionEndpoints();
app.MapHostEntityEndpoints();
app.MapReportEndpoints();
app.MapSettingsEndpoints();
app.MapAuditEndpoints();
app.MapV2DetectionEndpoints();
app.MapNotificationAndLlmEndpoints();

app.Run();

public partial class Program;

internal sealed class ServerSqlitePragmaInterceptor : DbConnectionInterceptor
{
    private const string Pragmas = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        if (connection is SqliteConnection sqlite)
        {
            using var cmd = sqlite.CreateCommand();
            cmd.CommandText = Pragmas;
            cmd.ExecuteNonQuery();
        }
        base.ConnectionOpened(connection, eventData);
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        if (connection is SqliteConnection sqlite)
        {
            await using var cmd = sqlite.CreateCommand();
            cmd.CommandText = Pragmas;
            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await base.ConnectionOpenedAsync(connection, eventData, cancellationToken).ConfigureAwait(false);
    }
}
