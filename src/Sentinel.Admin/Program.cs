using Microsoft.Extensions.Hosting.WindowsServices;
using Sentinel.Admin.Components;
using Sentinel.Admin.Services;
using Sentinel.Shared.Infrastructure;
using Serilog;

var logPath = Path.Combine(SentinelPaths.Logs, "admin-.log");

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(logPath, rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args,
        ContentRootPath = WindowsServiceHelpers.IsWindowsService() ? AppContext.BaseDirectory : null
    });
    builder.WebHost.UseStaticWebAssets();

    builder.Host.UseSerilog();
    builder.Host.UseWindowsService(options =>
    {
        options.ServiceName = SentinelEndpoints.AdminServiceName;
    });

    var configuredUrls = builder.Configuration["Urls"]
        ?? Environment.GetEnvironmentVariable("ASPNETCORE_URLS")
        ?? SentinelEndpoints.AdminUrl;
    if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
    {
        builder.WebHost.UseUrls(configuredUrls);
    }

    var serverUrl = (builder.Configuration["ServerUrl"] ?? SentinelEndpoints.ServerApiUrl).TrimEnd('/');

    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents(options =>
        {
            options.DetailedErrors = builder.Environment.IsDevelopment();
        });

    builder.Services.AddSingleton(new AdminServerOptions(serverUrl));

    builder.Services.AddHttpClient("SentinelServer", client =>
    {
        client.BaseAddress = new Uri(serverUrl + "/");
        client.Timeout = TimeSpan.FromSeconds(120);
    });

    builder.Services.AddHttpClient("SentinelReports", client =>
    {
        client.BaseAddress = new Uri(serverUrl + "/");
        client.Timeout = TimeSpan.FromMinutes(2);
    });

    builder.Services.AddScoped<AdminSessionState>();
    builder.Services.AddScoped<SentinelApiClient>();
    builder.Services.AddScoped<LiveHubClient>();
    builder.Services.AddScoped<ToastService>();
    builder.Services.AddScoped<ThemeService>();
    builder.Services.AddScoped<LocalizationService>();

    var app = builder.Build();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
    }

    app.UseStaticFiles();
    app.MapStaticAssets();
    app.UseAntiforgery();

    app.MapGet("/favicon.ico", () => Results.Redirect("/favicon.svg"));

    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode();

    Log.Information("SENTINEL Console d'administration démarrée — URL locale : {Urls} — Serveur : {ServerUrl}", configuredUrls, serverUrl);
    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Arrêt inattendu de la console d'administration SENTINEL.");
}
finally
{
    Log.CloseAndFlush();
}
