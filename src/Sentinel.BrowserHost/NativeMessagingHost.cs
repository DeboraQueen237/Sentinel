using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.BrowserHost;

/// <summary>
/// Hôte Native Messaging (Chrome / Edge) implémentant le protocole préfixé par 4 octets
/// <c>Int32</c> little-endian sur stdin/stdout et relayant de manière bidirectionnelle
/// vers <c>Sentinel.Agent.Ipc</c> (<see cref="IpcClientKind.BrowserHost"/>).
/// </summary>
public sealed class NativeMessagingHost : IDisposable
{
    private const int MaxNativeMessageBytes = 1024 * 1024; // 1 Mo max (spécification Chrome)

    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private readonly SemaphoreSlim _stdoutLock = new(1, 1);
    private readonly Channel<IpcMessage> _toAgent = Channel.CreateBounded<IpcMessage>(new BoundedChannelOptions(256)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true
    });

    private readonly CancellationTokenSource _cts = new();
    private volatile bool _agentConnected;
    private IpcClientSettings _lastSettings = new(true, true, true, OperatingMode.Learning, Array.Empty<string>());

    public NativeMessagingHost(Stream? stdin = null, Stream? stdout = null)
    {
        _stdin = stdin ?? Console.OpenStandardInput();
        _stdout = stdout ?? Console.OpenStandardOutput();
    }

    public async Task RunAsync(CancellationToken externalToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, externalToken);
        var ct = linked.Token;

        var pipeTask = Task.Run(() => PipeConnectionLoopAsync(ct), ct);
        var stdinTask = Task.Run(() => StdinReadLoopAsync(ct), ct);

        // Si le navigateur ferme stdin, l'hôte doit se terminer proprement.
        await stdinTask;
        linked.Cancel();
        try { await pipeTask; } catch { /* ignoré */ }
    }

    private async Task StdinReadLoopAsync(CancellationToken ct)
    {
        var lenBuf = new byte[4];
        while (!ct.IsCancellationRequested)
        {
            var readLen = await ReadExactAsync(_stdin, lenBuf, ct);
            if (!readLen)
            {
                break; // EOF : le navigateur a fermé le canal Native Messaging.
            }

            var payloadLen = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
            if (payloadLen <= 0 || payloadLen > MaxNativeMessageBytes)
            {
                break;
            }

            var payloadBuf = new byte[payloadLen];
            if (!await ReadExactAsync(_stdin, payloadBuf, ct))
            {
                break;
            }

            try
            {
                await HandleBrowserMessageAsync(payloadBuf, ct);
            }
            catch
            {
                // Ignore une trame malformée sans interrompre le pont.
            }
        }
    }

    private async Task HandleBrowserMessageAsync(byte[] utf8Json, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(utf8Json);
        var root = doc.RootElement;
        var msgType = root.TryGetProperty("type", out var tp) ? tp.GetString() : null;

        switch (msgType)
        {
            case "ping":
            case "getStatus":
                await WriteNativeMessageAsync(new
                {
                    type = "status",
                    connected = _agentConnected,
                    browserEnabled = _lastSettings.BrowserEnabled,
                    mode = _lastSettings.Mode.ToString(),
                    blockedDomains = _lastSettings.BlockedDomains
                }, ct);
                break;

            case "event":
                var evt = ConvertBrowserPayloadToEvent(root);
                if (evt is not null)
                {
                    _toAgent.Writer.TryWrite(IpcMessage.Create(IpcProtocol.Event, evt));
                }
                break;
        }
    }

    public static SecurityEvent? ConvertBrowserPayloadToEvent(JsonElement root)
    {
        var eventType = root.TryGetProperty("eventType", out var et) ? et.GetString() : EventTypes.UrlVisited;
        if (string.IsNullOrWhiteSpace(eventType))
        {
            eventType = EventTypes.UrlVisited;
        }

        var rawUrl = root.TryGetProperty("url", out var u) ? u.GetString() : null;
        var sanitizedUrl = SanitizeUrl(rawUrl, out var parsedDomain, out var scheme);
        var domain = root.TryGetProperty("domain", out var d) && !string.IsNullOrWhiteSpace(d.GetString())
            ? d.GetString()!.Trim().ToLowerInvariant()
            : parsedDomain;

        if (string.IsNullOrWhiteSpace(domain) && string.IsNullOrWhiteSpace(sanitizedUrl))
        {
            return null;
        }

        var attrs = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(sanitizedUrl)) attrs[AttributeKeys.Url] = sanitizedUrl;
        if (!string.IsNullOrWhiteSpace(domain)) attrs[AttributeKeys.Domain] = domain;
        if (!string.IsNullOrWhiteSpace(scheme)) attrs[AttributeKeys.UrlScheme] = scheme;

        if (root.TryGetProperty("referrer", out var rf) && !string.IsNullOrWhiteSpace(rf.GetString()))
        {
            var cleanRef = SanitizeUrl(rf.GetString(), out _, out _);
            if (!string.IsNullOrWhiteSpace(cleanRef))
            {
                attrs[AttributeKeys.Referrer] = cleanRef;
            }
        }

        if (root.TryGetProperty("redirectCount", out var rc) && rc.ValueKind == JsonValueKind.Number && rc.TryGetInt32(out var redirs))
        {
            attrs[AttributeKeys.RedirectCount] = redirs.ToString(CultureInfo.InvariantCulture);
        }

        if (root.TryGetProperty("tabId", out var tid) && tid.ValueKind != JsonValueKind.Null)
        {
            attrs[AttributeKeys.TabId] = tid.ToString();
        }

        if (root.TryGetProperty("browser", out var br) && !string.IsNullOrWhiteSpace(br.GetString()))
        {
            attrs[AttributeKeys.Browser] = br.GetString()!;
        }

        if (root.TryGetProperty("fileName", out var fn) && !string.IsNullOrWhiteSpace(fn.GetString()))
        {
            attrs[AttributeKeys.FileName] = Path.GetFileName(fn.GetString()!);
        }

        var subject = !string.IsNullOrWhiteSpace(domain) ? domain : sanitizedUrl!;
        var hints = string.IsNullOrWhiteSpace(domain) ? null : $"domain:{domain}";

        return SecurityEvent.Create(
            hostId: string.Empty,
            userId: Environment.UserName,
            EventCategory.Browser,
            eventType,
            subject,
            attrs,
            hints);
    }

    /// <summary>
    /// Supprime toute information d'authentification, chaîne de requête (?…) ou fragment (#…)
    /// afin de ne jamais capturer de jetons, mots de passe ou formulaires (doc §2.1, §6.8).
    /// </summary>
    public static string? SanitizeUrl(string? rawUrl, out string? domain, out string? scheme)
    {
        domain = null;
        scheme = null;
        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            return null;
        }

        if (!Uri.TryCreate(rawUrl.Trim(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        domain = uri.Host.Trim().TrimEnd('.').ToLowerInvariant();
        scheme = uri.Scheme.ToLowerInvariant();
        var portPart = uri.IsDefaultPort ? string.Empty : $":{uri.Port}";
        var pathPart = uri.AbsolutePath.Length > 200 ? uri.AbsolutePath[..200] : uri.AbsolutePath;
        return $"{scheme}://{domain}{portPart}{pathPart}";
    }

    private async Task PipeConnectionLoopAsync(CancellationToken ct)
    {
        var delaySeconds = 2;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(3000, ct);

                delaySeconds = 2;
                _agentConnected = true;
                await NotifyExtensionStatusAsync(ct);

                using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
                {
                    AutoFlush = true
                };

                var hello = IpcMessage.Create(
                    IpcProtocol.Hello,
                    new IpcHello(IpcClientKind.BrowserHost, Environment.UserName, Process.GetCurrentProcess().SessionId, "1.0.0"));
                await writer.WriteLineAsync(SentinelJson.Serialize(hello).AsMemory(), ct);

                using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var readTask = PipeReadLoopAsync(reader, sessionCts.Token);
                var writeTask = PipeWriteLoopAsync(writer, sessionCts.Token);

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
                // Agent indisponible : nouvelle tentative avec backoff.
            }
            finally
            {
                if (_agentConnected)
                {
                    _agentConnected = false;
                    try { await NotifyExtensionStatusAsync(ct); } catch { /* ignoré */ }
                }
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

    private async Task PipeReadLoopAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line is null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            var msg = SentinelJson.Deserialize<IpcMessage>(line);
            if (msg is null) continue;

            switch (msg.Type)
            {
                case IpcProtocol.Welcome:
                case IpcProtocol.ClientSettings:
                    var settings = msg.As<IpcClientSettings>();
                    if (settings is not null)
                    {
                        _lastSettings = settings;
                        await WriteNativeMessageAsync(new
                        {
                            type = "settings",
                            connected = true,
                            browserEnabled = settings.BrowserEnabled,
                            mode = settings.Mode.ToString(),
                            blockedDomains = settings.BlockedDomains
                        }, ct);
                    }
                    break;

                case IpcProtocol.CloseTab:
                    var closeCmd = msg.As<BrowserCommand>();
                    if (closeCmd is not null)
                    {
                        await WriteNativeMessageAsync(new
                        {
                            type = "closeTab",
                            tabId = closeCmd.TabId,
                            url = closeCmd.Url,
                            reason = closeCmd.Reason
                        }, ct);
                    }
                    break;

                case IpcProtocol.BlockDomains:
                    var blockCmd = msg.As<BrowserCommand>();
                    if (blockCmd is not null)
                    {
                        _lastSettings = _lastSettings with
                        {
                            BlockedDomains = blockCmd.Domains ?? Array.Empty<string>()
                        };
                        await WriteNativeMessageAsync(new
                        {
                            type = "blockDomains",
                            domains = blockCmd.Domains ?? Array.Empty<string>(),
                            reason = blockCmd.Reason
                        }, ct);
                    }
                    break;
            }
        }
    }

    private async Task PipeWriteLoopAsync(StreamWriter writer, CancellationToken ct)
    {
        await foreach (var msg in _toAgent.Reader.ReadAllAsync(ct))
        {
            var line = SentinelJson.Serialize(msg);
            await writer.WriteLineAsync(line.AsMemory(), ct);
        }
    }

    private Task NotifyExtensionStatusAsync(CancellationToken ct) =>
        WriteNativeMessageAsync(new
        {
            type = "status",
            connected = _agentConnected,
            browserEnabled = _lastSettings.BrowserEnabled,
            mode = _lastSettings.Mode.ToString(),
            blockedDomains = _lastSettings.BlockedDomains
        }, ct);

    private async Task WriteNativeMessageAsync<T>(T payload, CancellationToken ct)
    {
        var json = SentinelJson.Serialize(payload);
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length > MaxNativeMessageBytes)
        {
            return;
        }

        var lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, bytes.Length);

        await _stdoutLock.WaitAsync(ct);
        try
        {
            await _stdout.WriteAsync(lenBuf, ct);
            await _stdout.WriteAsync(bytes, ct);
            await _stdout.FlushAsync(ct);
        }
        finally
        {
            _stdoutLock.Release();
        }
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct);
            if (read == 0)
            {
                return false;
            }
            offset += read;
        }
        return true;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _toAgent.Writer.TryComplete();
        _stdoutLock.Dispose();
        _cts.Dispose();
    }
}
