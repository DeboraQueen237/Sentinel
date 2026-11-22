using Sentinel.Shared.Infrastructure;
using Sentinel.Watchdog;
using Serilog;

var logPath = Path.Combine(SentinelPaths.Logs, "watchdog-.log");
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.File(
        logPath,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        shared: true,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddSerilog(Log.Logger, dispose: true);

    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = SentinelEndpoints.WatchdogServiceName;
    });

    builder.Services.Configure<WatchdogOptions>(builder.Configuration.GetSection(WatchdogOptions.SectionName));
    builder.Services.AddHostedService<WatchdogWorker>();

    var host = builder.Build();
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Arrêt inattendu de Sentinel.Watchdog.");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

return 0;
