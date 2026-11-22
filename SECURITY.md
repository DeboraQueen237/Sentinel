# Politique de sécurité — SENTINEL

## Versions prises en charge

| Version | Support sécurité |
|---|---|
| `2.0.x` (`develop`) | Active |
| `1.0.x` (`main`) | Maintenance critique uniquement |

## Principes de sécurité défensive

- **Usage strictement défensif** : SENTINEL est un EDR léger complémentaire à Microsoft Defender. Il ne contient aucun code offensif, keylogger ni capacité d'exfiltration.
- **Données locales et vie privée** : l'IA (Ollama) et l'analyse tournent 100 % localement. Seules les mises à jour entrantes de flux de renseignement publics (opt-in) ou les recherches VirusTotal explicites par hash initient des requêtes sortantes.
- **Décisions déterministes et réversibles** : le LLM ne déclenche jamais d'action ; toute action automatique crée un ticket réversible sans suppression définitive.
- **Gestion des secrets** : aucune clé API, certificat ou mot de passe n'est stocké dans Git. En développement, utiliser `dotnet user-secrets` ; en production Windows, les secrets sont protégés via DPAPI (`LocalMachine`) et ACL NTFS restreintes sur `%ProgramData%\Sentinel`.

## Signaler une vulnérabilité

Si vous découvrez une faille de sécurité dans SENTINEL (contournement d'authentification, prompt injection, élévation de privilèges via l'agent, fuite de contenu utilisateur, rupture de la chaîne d'intégrité) :

1. **Ne créez pas d'issue publique** détaillant l'exploitation.
2. Ouvrez un **GitHub Security Advisory** privé sur le dépôt [DeboraQueen237/Sentinel](https://github.com/DeboraQueen237/Sentinel/security/advisories) ou contactez le mainteneur directement.
3. Incluez : la version affectée, les étapes de reproduction (sur environnement isolé), l'impact estimé et, si possible, un correctif proposé.

Un accusé de réception est visé sous 72 h, suivi d'une évaluation et d'un correctif publié avec note dans `CHANGELOG.md`.
