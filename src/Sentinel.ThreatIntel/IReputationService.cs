using Sentinel.Shared.Api;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Contrat principal du moteur de renseignement sur les menaces (Mission 4 — SENTINEL v2).
/// Fournit des recherches locales ultra-rapides (filtre de Bloom + SQLite indexé),
/// un fonctionnement 100 % hors ligne sur la dernière base connue, et l'interrogation
/// strictement à la demande de VirusTotal v3 (hash uniquement).
/// </summary>
public interface IReputationService
{
    /// <summary>Recherche locale d'un condensat SHA-256 malveillant connu.</summary>
    ThreatIntelMatch? LookupHash(string sha256);

    /// <summary>
    /// Recherche locale d'un domaine malveillant, incluant la correspondance sous-domaine → domaine parent
    /// (ex. <c>sub.evil.xyz</c> correspond à <c>evil.xyz</c>).
    /// </summary>
    ThreatIntelMatch? LookupDomain(string domain);

    /// <summary>Recherche locale d'une URL malveillante (avec normalisation schéma, casse et slash final).</summary>
    ThreatIntelMatch? LookupUrl(string url);

    /// <summary>Recherche locale d'une adresse IP malveillante (IPv4 ou IPv6).</summary>
    ThreatIntelMatch? LookupIp(string ip);

    /// <summary>
    /// Recherche unifiée mesurant <c>ElapsedMs</c> via <see cref="System.Diagnostics.Stopwatch"/>,
    /// retournant un score suggéré (90–96) et une justification datée explicite en cas de correspondance.
    /// </summary>
    ThreatIntelLookupDto Lookup(string indicatorType, string value);

    /// <summary>Retourne l'état complet du cache local et de chacun des flux configurés.</summary>
    ThreatIntelStatusDto GetStatus();

    /// <summary>Rafraîchit les flux activés en mode différentiel et reconstruit atomiquement le filtre de Bloom.</summary>
    Task<ThreatIntelStatusDto> RefreshNowAsync(CancellationToken ct = default);

    /// <summary>
    /// Interroge VirusTotal v3 par hash SHA-256 uniquement, strictement à la demande
    /// et exclusivement si <c>EnableVirusTotalOnDemand</c> est activé et la clé API configurée.
    /// </summary>
    Task<ThreatIntelLookupDto?> QueryVirusTotalHashOnDemandAsync(string sha256, CancellationToken ct = default);
}
