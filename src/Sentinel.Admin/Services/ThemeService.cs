using Microsoft.JSInterop;

namespace Sentinel.Admin.Services;

/// <summary>Gère le thème Clair / Sombre persisté dans localStorage et synchronisé avec les graphiques/graphe.</summary>
public sealed class ThemeService
{
    private readonly IJSRuntime _js;
    private bool _initialized;

    public ThemeService(IJSRuntime js)
    {
        _js = js;
    }

    public string CurrentTheme { get; private set; } = "dark";
    public bool IsDark => !string.Equals(CurrentTheme, "light", StringComparison.OrdinalIgnoreCase);

    public event Action<string>? ThemeChanged;

    public async Task InitializeAsync()
    {
        if (_initialized) return;
        try
        {
            var theme = await _js.InvokeAsync<string>("sentinelUtils.getTheme");
            CurrentTheme = string.Equals(theme, "light", StringComparison.OrdinalIgnoreCase) ? "light" : "dark";
            _initialized = true;
            ThemeChanged?.Invoke(CurrentTheme);
        }
        catch
        {
            // Mode sombre par défaut
        }
    }

    public async Task ToggleAsync()
    {
        try
        {
            var next = await _js.InvokeAsync<string>("sentinelUtils.toggleTheme");
            CurrentTheme = string.Equals(next, "light", StringComparison.OrdinalIgnoreCase) ? "light" : "dark";
            _initialized = true;
            ThemeChanged?.Invoke(CurrentTheme);
        }
        catch
        {
            // Ignoré si circuit déconnecté
        }
    }
}
