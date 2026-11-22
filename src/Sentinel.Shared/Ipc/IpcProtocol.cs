using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Shared.Models;

namespace Sentinel.Shared.Ipc;

/// <summary>
/// Protocole IPC local (Named Pipe) entre Sentinel.Agent (serveur, service LocalSystem) et les clients
/// de la session utilisateur : Sentinel.Tray (presse-papiers, rythme de frappe, notifications, icône)
/// et Sentinel.BrowserHost (Native Messaging de l'extension navigateur).
/// Trame : une ligne JSON UTF-8 par message (« JSON Lines »), sérialisée avec SentinelJson.Options.
/// </summary>
public static class IpcProtocol
{
    /// <summary>Nom du pipe (\\.\pipe\Sentinel.Agent.Ipc).</summary>
    public const string PipeName = "Sentinel.Agent.Ipc";

    // Client -> Agent
    public const string Hello = "hello";           // IpcHello
    public const string Event = "event";           // SecurityEvent (UserId/HostId complétés par l'agent si vides)
    public const string Ping = "ping";

    // Agent -> Client
    public const string Welcome = "welcome";       // IpcClientSettings
    public const string Notify = "notify";         // UserNotification (niveau 2 / sensibilisation)
    public const string ClientSettings = "settings"; // IpcClientSettings
    public const string CloseTab = "browser.closeTab";       // BrowserCommand
    public const string BlockDomains = "browser.blockDomains"; // BrowserCommand (liste complète des domaines bloqués)
    public const string LockSession = "session.lock";        // (Tray exécute LockWorkStation dans la session utilisateur)
    public const string Pong = "pong";
}

public sealed record IpcMessage(string Type, JsonElement? Payload)
{
    public static IpcMessage Create<T>(string type, T payload) =>
        new(type, JsonSerializer.SerializeToElement(payload, Json.SentinelJson.Options));

    public T? As<T>() => Payload is { } p ? p.Deserialize<T>(Json.SentinelJson.Options) : default;
}

public enum IpcClientKind { Tray, BrowserHost }

public sealed record IpcHello(IpcClientKind Kind, string UserName, int SessionId, string Version);

public sealed record IpcClientSettings(
    bool ClipboardEnabled,
    bool TypingRhythmEnabled,
    bool BrowserEnabled,
    OperatingMode Mode,
    IReadOnlyList<string> BlockedDomains);

public enum NotificationSeverity { Info, Warning, Critical }

public sealed record UserNotification(string Title, string Message, NotificationSeverity Severity, string? AlertId = null);

public sealed record BrowserCommand(string? TabId, string? Url, IReadOnlyList<string>? Domains, string? Reason);
