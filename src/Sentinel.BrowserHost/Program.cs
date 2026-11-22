using Sentinel.BrowserHost;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

using var host = new NativeMessagingHost();
await host.RunAsync(cts.Token);
return 0;
