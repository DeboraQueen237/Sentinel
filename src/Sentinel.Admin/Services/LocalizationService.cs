using Microsoft.JSInterop;

namespace Sentinel.Admin.Services;

/// <summary>
/// Service de localisation Français / Anglais (v2 Mission 11) persisté dans localStorage
/// avec bascule instantanée depuis la barre supérieure de la console SOC.
/// </summary>
public sealed class LocalizationService
{
    private readonly IJSRuntime _js;
    private bool _initialized;

    public LocalizationService(IJSRuntime js)
    {
        _js = js;
    }

    public string CurrentLanguage { get; private set; } = "fr";
    public bool IsEnglish => string.Equals(CurrentLanguage, "en", StringComparison.OrdinalIgnoreCase);

    public event Action<string>? LanguageChanged;

    public async Task InitializeAsync()
    {
        if (_initialized) return;
        try
        {
            var stored = await _js.InvokeAsync<string?>("localStorage.getItem", "sentinel.lang");
            if (stored is not null &&
                (string.Equals(stored, "en", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(stored, "fr", StringComparison.OrdinalIgnoreCase)))
            {
                CurrentLanguage = stored.ToLowerInvariant();
            }
            _initialized = true;
            LanguageChanged?.Invoke(CurrentLanguage);
        }
        catch
        {
            // Français par défaut
        }
    }

    public async Task ToggleAsync()
    {
        var next = IsEnglish ? "fr" : "en";
        await SetLanguageAsync(next);
    }

    public async Task SetLanguageAsync(string lang)
    {
        CurrentLanguage = string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase) ? "en" : "fr";
        _initialized = true;
        try
        {
            await _js.InvokeVoidAsync("localStorage.setItem", "sentinel.lang", CurrentLanguage);
        }
        catch { /* ignoré si circuit déconnecté */ }
        LanguageChanged?.Invoke(CurrentLanguage);
    }

    /// <summary>Retourne la chaîne traduite selon la langue active.</summary>
    public string T(string fr, string en) => IsEnglish ? en : fr;
}
