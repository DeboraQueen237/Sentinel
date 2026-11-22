using Sentinel.Shared.Infrastructure;

namespace Sentinel.Watchdog;

public sealed class WatchdogOptions
{
    public const string SectionName = "Watchdog";

    public int CheckIntervalSeconds { get; set; } = 10;
    public int IntegrityIntervalSeconds { get; set; } = 60;
    public List<string> MonitoredServices { get; set; } =
    [
        SentinelEndpoints.AgentServiceName,
        SentinelEndpoints.ServerServiceName
    ];
    public string InstallDirectory { get; set; } = string.Empty;
}
