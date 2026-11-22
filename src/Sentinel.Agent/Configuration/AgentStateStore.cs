using Microsoft.Extensions.Logging;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Configuration;

/// <summary>État local persistant de l'agent (identifiant de poste, version de configuration).</summary>
public sealed class AgentPersistedState
{
    public string HostId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public long SettingsVersion { get; set; }
    public SentinelSettings Settings { get; set; } = new();
}

/// <summary>
/// Gère la persistance atomique de <see cref="AgentPersistedState"/> dans <see cref="SentinelPaths.AgentStateFile"/>
/// et notifie les collecteurs/composants lors d'une mise à jour à chaud de <see cref="SentinelSettings"/>.
/// </summary>
public sealed class AgentStateStore
{
    private readonly string _stateFilePath;
    private readonly ILogger<AgentStateStore> _logger;
    private readonly object _gate = new();
    private AgentPersistedState _state;

    public event Action<SentinelSettings>? SettingsChanged;

    public AgentStateStore(ILogger<AgentStateStore> logger, string? stateFilePath = null)
    {
        _logger = logger;
        _stateFilePath = stateFilePath ?? SentinelPaths.AgentStateFile;
        _state = LoadOrCreate();
    }

    public string HostId
    {
        get { lock (_gate) return _state.HostId; }
    }

    public long SettingsVersion
    {
        get { lock (_gate) return _state.SettingsVersion; }
    }

    public SentinelSettings CurrentSettings
    {
        get { lock (_gate) return _state.Settings; }
    }

    public void UpdateSettings(SentinelSettings settings, long version)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_gate)
        {
            if (version > 0 && version <= _state.SettingsVersion)
            {
                return;
            }

            _state.Settings = settings;
            if (version > 0)
            {
                _state.SettingsVersion = version;
            }
            SaveLocked();
        }

        _logger.LogInformation("Configuration SENTINEL mise à jour (version {Version}, mode {Mode}).", version, settings.Mode);
        SettingsChanged?.Invoke(settings);
    }

    private AgentPersistedState LoadOrCreate()
    {
        try
        {
            if (File.Exists(_stateFilePath))
            {
                var json = File.ReadAllText(_stateFilePath);
                var loaded = SentinelJson.Deserialize<AgentPersistedState>(json);
                if (loaded is not null && !string.IsNullOrWhiteSpace(loaded.HostId))
                {
                    loaded.Settings ??= new SentinelSettings();
                    return loaded;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de lire {Path} ; régénération de l'état local de l'agent.", _stateFilePath);
        }

        var sanitizedHost = new string(Environment.MachineName
            .Where(c => char.IsLetterOrDigit(c) || c == '-')
            .ToArray())
            .ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(sanitizedHost))
        {
            sanitizedHost = "host";
        }

        var fresh = new AgentPersistedState
        {
            HostId = $"{sanitizedHost}-{Guid.NewGuid():N}"[..Math.Min(sanitizedHost.Length + 9, 48)],
            CreatedAtUtc = DateTimeOffset.UtcNow,
            SettingsVersion = 0,
            Settings = new SentinelSettings()
        };

        _state = fresh;
        SaveLocked();
        return fresh;
    }

    private void SaveLocked()
    {
        try
        {
            var dir = Path.GetDirectoryName(_stateFilePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var tmp = _stateFilePath + ".tmp";
            File.WriteAllText(tmp, SentinelJson.Serialize(_state));
            File.Move(tmp, _stateFilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec de sauvegarde de l'état de l'agent dans {Path}.", _stateFilePath);
        }
    }
}
