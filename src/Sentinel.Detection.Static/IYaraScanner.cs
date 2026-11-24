using Sentinel.Shared.Api;

namespace Sentinel.Detection.Static;

/// <summary>
/// Contrat du moteur d'analyse YARA de SENTINEL v2.
/// Utilise <c>dnYara</c> (<c>libyara</c>) lorsque la bibliotheque native est disponible,
/// et bascule automatiquement sur <see cref="ManagedYaraFallbackEngine"/> dans le cas contraire.
/// </summary>
public interface IYaraScanner : IDisposable
{
    /// <summary>Nom explicite du moteur actif (<c>"dnYara (libyara)"</c> ou <c>"ManagedFallback (libyara indisponible)"</c>).</summary>
    string EngineName { get; }

    /// <summary>Indique si le moteur de repli manage est actif.</summary>
    bool IsUsingFallback { get; }

    /// <summary>Raison detaillee de la bascule sur le repli manage, ou <c>null</c> si <c>dnYara</c> natif est actif.</summary>
    string? FallbackReason { get; }

    /// <summary>Nombre total de regles actuellement chargees.</summary>
    int RuleCount { get; }

    /// <summary>Nombre de regles actuellement actives.</summary>
    int EnabledRuleCount { get; }

    /// <summary>Erreurs non fatales collectees lors du dernier chargement ou rechargement.</summary>
    IReadOnlyList<YaraLoadError> LoadErrors { get; }

    /// <summary>Evenement emis apres un rechargement a chaud.</summary>
    event EventHandler<YaraRuleLoadResult>? RulesReloaded;

    /// <summary>Charge recursivement les regles <c>.yar</c> / <c>.yara</c> d'un dossier (defaut : <c>%ProgramData%\Sentinel\rules\yara</c>).</summary>
    YaraRuleLoadResult LoadFromDirectory(string? directory = null);

    /// <summary>Charge recursivement les regles depuis plusieurs dossiers.</summary>
    YaraRuleLoadResult LoadFromDirectories(IEnumerable<string> directories);

    /// <summary>Charge une ou plusieurs regles YARA depuis une chaine source en memoire.</summary>
    YaraRuleLoadResult LoadRuleString(string yaraSource, string sourceName = "<memory>");

    /// <summary>Recharge les regles depuis les derniers dossiers configures.</summary>
    YaraRuleLoadResult Reload();

    /// <summary>Active le rechargement a chaud avec anti-rebond sur un dossier de regles.</summary>
    void EnableHotReload(string? directory = null, int debounceMs = 300);

    /// <summary>Desactive la surveillance de rechargement a chaud.</summary>
    void DisableHotReload();

    /// <summary>Active ou desactive une regle par son identifiant.</summary>
    bool SetRuleEnabled(string ruleId, bool enabled);

    /// <summary>Definit la liste des identifiants de regles desactivees.</summary>
    void SetDisabledRules(IEnumerable<string> disabledRuleIds);

    /// <summary>Retourne le resume de toutes les regles chargees pour la console d'administration.</summary>
    IReadOnlyList<RuleSummaryDto> GetRuleSummaries();

    /// <summary>Analyse un fichier sur disque contre toutes les regles actives.</summary>
    YaraScanReport ScanFile(string filePath, CancellationToken ct = default);

    /// <summary>Analyse un tampon memoire contre toutes les regles actives.</summary>
    YaraScanReport ScanBytes(byte[] data, CancellationToken ct = default);
}
