using Sentinel.Agent.Collectors;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Ipc;
using Sentinel.Agent.Pipeline;
using Sentinel.Agent.Response;
using Sentinel.Agent.Security;
using Sentinel.Agent.Storage;
using Sentinel.Agent.Transport;
using Sentinel.Shared.Infrastructure;
using Serilog;

var logPath = Path.Combine(SentinelPaths.Logs, "agent-.log");
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        logPath,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        shared: true,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext} {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddSerilog(Log.Logger, dispose: true);

    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = SentinelEndpoints.AgentServiceName;
    });

    builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));

    // État local & stockage persistant
    builder.Services.AddSingleton<AgentStateStore>();
    builder.Services.AddSingleton(sp =>
    {
        var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentOptions>>().Value;
        return new SqliteEventOutbox(SentinelPaths.AgentOutboxDatabase, Math.Max(1000, opts.MaxOutboxEvents));
    });

    // Pipeline d'événements
    builder.Services.AddSingleton<AgentEventPipeline>();
    builder.Services.AddSingleton<IEventSink>(sp => sp.GetRequiredService<AgentEventPipeline>());
    builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentEventPipeline>());

    // Collecteurs
    builder.Services.AddSingleton<ProcessEnricher>();
    builder.Services.AddSingleton<IEventCollector, ProcessCollector>();
    builder.Services.AddSingleton<IEventCollector, NetworkCollector>();
    builder.Services.AddSingleton<IEventCollector, FileSystemCollector>();
    builder.Services.AddSingleton<IEventCollector, SessionCollector>();
    builder.Services.AddSingleton<IEventCollector, DeviceCollector>();
    builder.Services.AddSingleton<IEventCollector, InstallationCollector>();

    builder.Services.AddSingleton<CollectorHostService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<CollectorHostService>());

    // Exécuteur d'actions réversibles
    builder.Services.AddSingleton<QuarantineManager>();
    builder.Services.AddSingleton<HostsFileManager>();
    builder.Services.AddSingleton<FirewallManager>();
    builder.Services.AddSingleton<ProcessController>();
    builder.Services.AddSingleton<FolderProtector>();
    builder.Services.AddSingleton<DeviceController>();
    builder.Services.AddSingleton<ActionExecutor>();

    // IPC Named Pipe (Sentinel.Tray & Sentinel.BrowserHost)
    builder.Services.AddSingleton<AgentIpcServer>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentIpcServer>());

    // Auto-protection & transport gRPC mTLS
    builder.Services.AddSingleton<SelfIntegrityChecker>();
    builder.Services.AddHostedService<ServerTransportWorker>();

    var host = builder.Build();
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Arrêt inattendu de Sentinel.Agent.");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

return 0;
