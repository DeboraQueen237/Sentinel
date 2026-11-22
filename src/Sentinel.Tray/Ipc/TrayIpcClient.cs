using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Tray.Ipc;

/// <summary>
/// Client Named Pipe vers <c>Sentinel.Agent.Ipc</c> avec reconnexion automatique.
/// Transmet les événements du presse-papiers et de la dynamique de saisie, reçoit les réglages à chaud,
/// affiche les notifications utilisateur et exécute <c>LockWorkStation()</c> sur commande <c>session.lock</c>.
/// </summary>
public sealed class TrayIpcClient : IDisposable
{
    private readonly Channel<SecurityEvent> _outbound = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(256)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true
    });

    private readonly CancellationTokenSource _cts = new();
    private readonly Task _workerTask;
    private volatile bool _connected;

    public bool IsConnected => _connected;

    public event Action<bool>? ConnectionChanged;
    public event Action<IpcClientSettings>? SettingsReceived;
    public event Action<UserNotification>? NotificationReceived;

    public TrayIpcClient()
    {
        _workerTask = Task.Run(() => ConnectionLoopAsync(_cts.Token));
    }

    public void SendEvent(SecurityEvent evt)
    {
        _outbound.Writer.TryWrite(evt);
    }

    private async Task ConnectionLoopAsync(CancellationToken ct)
    {
        var delaySeconds = 2;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(3000, ct);

                delaySeconds = 2;
                SetConnected(true);

                using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
                {
                    AutoFlush = true
                };

                var hello = IpcMessage.Create(
                    IpcProtocol.Hello,
                    new IpcHello(IpcClientKind.Tray, Environment.UserName, Process.GetCurrentProcess().SessionId, "1.0.0"));
                await writer.WriteLineAsync(SentinelJson.Serialize(hello).AsMemory(), ct);

                using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var readTask = ReadLoopAsync(reader, sessionCts.Token);
                var writeTask = WriteLoopAsync(writer, sessionCts.Token);

                await Task.WhenAny(readTask, writeTask);
                sessionCts.Cancel();
                try { await Task.WhenAll(readTask, writeTask); } catch { /* ignoré */ }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                // Agent indisponible ou redémarré : reconnexion automatique.
            }
            finally
            {
                SetConnected(false);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            delaySeconds = Math.Min(delaySeconds * 2, 10);
        }
    }

    private async Task ReadLoopAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line is null)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var msg = SentinelJson.Deserialize<IpcMessage>(line);
            if (msg is null) continue;

            switch (msg.Type)
            {
                case IpcProtocol.Welcome:
                case IpcProtocol.ClientSettings:
                    var settings = msg.As<IpcClientSettings>();
                    if (settings is not null)
                    {
                        SettingsReceived?.Invoke(settings);
                    }
                    break;

                case IpcProtocol.Notify:
                    var notif = msg.As<UserNotification>();
                    if (notif is not null)
                    {
                        NotificationReceived?.Invoke(notif);
                    }
                    break;

                case IpcProtocol.LockSession:
                    LockWorkStation();
                    break;
            }
        }
    }

    private async Task WriteLoopAsync(StreamWriter writer, CancellationToken ct)
    {
        await foreach (var evt in _outbound.Reader.ReadAllAsync(ct))
        {
            var msg = IpcMessage.Create(IpcProtocol.Event, evt);
            var line = SentinelJson.Serialize(msg);
            await writer.WriteLineAsync(line.AsMemory(), ct);
        }
    }

    private void SetConnected(bool value)
    {
        if (_connected != value)
        {
            _connected = value;
            ConnectionChanged?.Invoke(value);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _outbound.Writer.TryComplete();
        try { _workerTask.Wait(TimeSpan.FromSeconds(2)); } catch { /* ignoré */ }
        _cts.Dispose();
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LockWorkStation();
}
