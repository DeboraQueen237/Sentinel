using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Sigma;

/// <summary>Contrat du moteur natif d'evaluation des regles Sigma de SENTINEL v2.</summary>
public interface ISigmaEngine : IDisposable
{
    /// <summary>Nombre total de regles actuellement chargees.</summary>
    int RuleCount { get; }

    /// <summary>Nombre de regles actuellement actives.</summary>
    int EnabledRuleCount { get; }

    /// <summary>Regles actuellement chargees.</summary>
    IReadOnlyList<SigmaRule> Rules { get; }

    /// <summary>Erreurs non fatales collectees lors du dernier chargement/rechargement.</summary>
    IReadOnlyList<SigmaLoadError> LoadErrors { get; }

    /// <summary>Notifie un rechargement a chaud effectue par le <see cref="FileSystemWatcher"/>.</summary>
    event EventHandler<SigmaRuleLoadResult>? RulesReloaded;

    /// <summary>Charge recursivement toutes les regles YAML (<c>.yml</c>, <c>.yaml</c>) d'un repertoire.</summary>
    SigmaRuleLoadResult LoadFromDirectory(string dir);

    /// <summary>Charge recursivement les regles de plusieurs repertoires.</summary>
    SigmaRuleLoadResult LoadFromDirectories(IEnumerable<string> directories);

    /// <summary>Charge directement une collection de regles en memoire.</summary>
    void LoadRules(IEnumerable<SigmaRule> rules);

    /// <summary>Parse et ajoute une regle YAML unique en memoire.</summary>
    SigmaRule LoadRuleYaml(string yamlContent, string sourceFile = "<memory>");

    /// <summary>Recharge les regles depuis le(s) dernier(s) repertoire(s) configure(s).</summary>
    SigmaRuleLoadResult Reload();

    /// <summary>Active le rechargement a chaud avec debounce sur un repertoire de regles.</summary>
    void EnableHotReload(string directory, int debounceMs = 300);

    /// <summary>Desactive la surveillance de rechargement a chaud.</summary>
    void DisableHotReload();

    /// <summary>Evalue un evenement contre toutes les regles Sigma actives applicables.</summary>
    IReadOnlyList<SigmaMatch> Evaluate(SecurityEvent evt);

    /// <summary>
    /// Evalue un evenement et synthetise un <see cref="ThreatAssessment"/> (<see cref="AssessmentSource.Sigma"/>),
    /// ou <c>null</c> si aucune regle ne correspond.
    /// </summary>
    ThreatAssessment? EvaluateAsAssessment(SecurityEvent evt);

    /// <summary>Active ou desactive une regle par son identifiant.</summary>
    bool SetRuleEnabled(string ruleId, bool enabled);

    /// <summary>Configure les identifiants de regles desactivees et les cibles exclues de l'evaluation.</summary>
    void SetExclusions(IEnumerable<string> disabledIds, IEnumerable<string> excludedTargets);

    /// <summary>Retourne le resume de toutes les regles chargees (avec leur compteur <c>MatchCount</c>).</summary>
    IReadOnlyList<RuleSummaryDto> GetRuleSummaries();
}
