using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Sentinel.Shared.Api;

namespace Sentinel.Admin.Services;

public sealed record AdminServerOptions(string ServerUrl);

public sealed record StoredAdminSession(string Token, string Username, DateTimeOffset ExpiresAt);

/// <summary>
/// État d'authentification Scoped par circuit Blazor, persisté dans ProtectedSessionStorage
/// pour survivre aux rechargements de page tout en restant isolé à l'onglet.
/// </summary>
public sealed class AdminSessionState
{
    private const string StorageKey = "sentinel.admin.session.v1";
    private readonly ProtectedSessionStorage _storage;
    private readonly ILogger<AdminSessionState> _logger;
    private bool _initialized;

    public AdminSessionState(ProtectedSessionStorage storage, ILogger<AdminSessionState> logger)
    {
        _storage = storage;
        _logger = logger;
    }

    public string? Token { get; private set; }
    public string? Username { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public bool IsInitialized => _initialized;

    public bool IsAuthenticated =>
        !string.IsNullOrWhiteSpace(Token) &&
        ExpiresAt.HasValue &&
        ExpiresAt.Value > DateTimeOffset.UtcNow.AddSeconds(10);

    public event Action? Changed;

    public async Task InitializeAsync()
    {
        if (_initialized) return;

        try
        {
            var result = await _storage.GetAsync<StoredAdminSession>(StorageKey);
            if (result.Success && result.Value is { } stored)
            {
                if (stored.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(10))
                {
                    Token = stored.Token;
                    Username = stored.Username;
                    ExpiresAt = stored.ExpiresAt;
                }
                else
                {
                    await ClearStorageQuietlyAsync();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Impossible de restaurer la session chiffrée (nouvelle session ou clé régénérée).");
            await ClearStorageQuietlyAsync();
        }
        finally
        {
            _initialized = true;
            Changed?.Invoke();
        }
    }

    public async Task SetSessionAsync(LoginResponse login)
    {
        Token = login.Token;
        Username = login.Username;
        ExpiresAt = login.ExpiresAt;
        _initialized = true;

        try
        {
            await _storage.SetAsync(StorageKey, new StoredAdminSession(login.Token, login.Username, login.ExpiresAt));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec de la persistance ProtectedSessionStorage.");
        }

        Changed?.Invoke();
    }

    public async Task ClearAsync()
    {
        Token = null;
        Username = null;
        ExpiresAt = null;
        await ClearStorageQuietlyAsync();
        Changed?.Invoke();
    }

    private async Task ClearStorageQuietlyAsync()
    {
        try
        {
            await _storage.DeleteAsync(StorageKey);
        }
        catch
        {
            // Ignoré si le circuit n'est plus connecté
        }
    }
}
