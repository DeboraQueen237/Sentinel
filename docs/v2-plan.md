# SENTINEL v2 — Audit de départ et plan d'implémentation

> Document préparatoire rédigé avant toute écriture de code v2.
> Branche de référence v1 : `main` (`2ee04a6`) — Branche d'intégration v2 : `develop`.

---

## 1. État de départ (v1.0.0)

### 1.1 Inventaire vérifié du dépôt
- **Plateforme** : .NET 10 LTS (`10.0.301`), gestion centralisée des packages (`Directory.Packages.props`), 15 projets dans `Sentinel.slnx` (~31 981 lignes C#/Razor hors `obj/`/`bin/`).
- **Build & Tests v1** : 15/15 projets compilés avec 0 erreur / 0 avertissement ; **70/70 tests verts** (`Sentinel.Core.Tests` : 34, `Sentinel.Agent.Tests` : 26, `Sentinel.Server.Tests` : 10).
- **IA locale détectée sur le poste** : **Ollama actif** sur `http://localhost:11434` avec le modèle installé **`qwen2.5-coder:3b`** (`1,93 Go`, ID `f72c60cabf62`).
- **Composants v1 présents** :
  - `Sentinel.Shared` : contrats modèles, enums, `MitreCatalog`, REST/SignalR, gRPC Protobuf, IPC Named Pipe, `SentinelPki` (ECDSA P-256 mTLS), `SecretProtector` (DPAPI), `HashChain`.
  - `Sentinel.AI` : `OllamaAssessor` (client HTTP `/api/chat`, `/api/tags`, `/api/embeddings`), `PromptBuilder` anti prompt-injection (`<donnees_non_fiables>`), `LlmResponseValidator`, backoff exponentiel 5 s → 15 s → 60 s.
  - `Sentinel.Core` : 44 règles déterministes, `BehavioralBaseline` (Welford + retour faux positif), `HybridScorer`, `CorrelationEngine` (composantes connexes, formule §8.2, 7 chaînes d'attaque, escalade 2ᵉ événement), `DecisionEngine` (matrice 0–4 réversible).
  - `Sentinel.Storage` : EF Core 10 SQLite WAL (14 tables), `HashChainWriter`, `IntegrityVerifier`, `RetentionCleaner`.
  - `Sentinel.Server` : API REST + SignalR (`:5180`), gRPC mTLS (`:5181`), authentification admin PBKDF2 (600 000 itérations) + 2FA TOTP, constructeur de graphe, rapports QuestPDF/JSON.
  - `Sentinel.Agent`, `Sentinel.Tray`, `Sentinel.BrowserHost`, `extension/` (MV3), `Sentinel.Watchdog`, `Sentinel.Installer` (WinForms + CLI), `Sentinel.Admin` (Blazor Server + Cytoscape.js/Chart.js locaux), `Sentinel.Simulation` (8 scénarios + 219 évts bénins, A vs B vs C).

---

## 2. Écarts constatés entre la documentation v1 et le code

| # | Domaine | Écart constaté | Correction prévue en v2 |
|---|---|---|---|
| E1 | **Modèle Ollama par défaut** | `LlmSettings.Model` vaut `"qwen2.5:7b"` dans `Settings.cs`, `Admin`, `Simulation` et la doc, alors que le modèle réellement installé sur la machine est **`qwen2.5-coder:3b`** (1,9 Go). | Basculer la valeur par défaut sur `qwen2.5-coder:3b`, ajouter la détection automatique des modèles Ollama installés (`GET /api/tags`) et recommander `3b`/`7b` selon la RAM dans l'installeur. |
| E2 | **Verrouillage anti-brute-force admin** | `docs/threat-model.md` et M9 mentionnent la robustesse de l'auth admin, mais `AuthService.LoginAsync` n'implémente pas encore le verrouillage temporaire après $N$ échecs successifs. | Implémenter un verrouillage progressif (ex. 5 échecs → verrouillage 15 min journalisé dans l'audit, réinitialisé après succès) en **M9**. |
| E3 | **ACL restrictives sur `%ProgramData%\Sentinel`** | `docs/threat-model.md` §2 mentionne des ACL NTFS restreintes à `SYSTEM`/`Administrators`, mais aucun code ne les applique encore automatiquement. | Implémenter `DirectorySecurityHardener` appliqué par l'installeur et vérifiable par le serveur/watchdog en **M9** et **M13**. |
| E4 | **Sources de détection natives Windows** | L'agent v1 collecte processus/réseau/fichiers/sessions/USB/installations mais ne lit ni **Microsoft Defender**, ni **Sysmon**, ni la journalisation **PowerShell 4104** / ETW AMSI, ni des **fichiers canaris**. | Implémentés en **M1**, **M6** et **M7**. |
| E5 | **Moteurs de détection standardisés** | Les 44 règles v1 sont codées en dur en C# (`RuleEngine.cs`) : pas de moteur **Sigma YAML**, pas de scan **YARA + analyse PE statique**, pas de **Threat Intelligence** externe, pas de classifieur **ML.NET**. | Implémentés via projets dédiés en **M2**, **M3**, **M4** et **M5**. |
| E6 | **Corrélation probabiliste & explicabilité** | `CorrelationEngine` v1 utilise des poids fixes (`0.3` / `0.8`) et une justification textuelle synthétique sans décomposition par source (Sigma/YARA/TI/ML/LLM/séquence) ni modèle probabiliste de transitions. | Ajout d'un modèle **Markov / Bayésien** adaptatif, récit chronologique structuré et boucle de retour réversible en **M8**. |
| E7 | **Installateur MSI (WiX v5)** | La v1 fournit un installeur WinForms/CLI (`Sentinel.Installer`) et un script ZIP, mais pas de package **MSI WiX v5**, pas de mise à jour majeure MSI ni de script de signature `build/sign.ps1`. | Ajout de `src/Sentinel.Installer.Msi/` (WiX v5), `build/build.ps1`, `build/sign.ps1` et détection Ollama/Defender/Sysmon en **M13**. |
| E8 | **Dashboard & Localisation** | La console v1 est uniquement en français et ne possède pas encore les vues dédiées Renseignement, Règles Sigma/YARA, Modèle ML, Canaris et Santé agent détaillée. | Ajout de toutes les pages v2 + localisation **FR / EN** + filtre tactique MITRE dans le graphe en **M11**. |

---

## 3. Dette technique identifiée en v1

1. **Avertissement EF Core `MultipleCollectionIncludeWarning`** observé dans les logs serveur lors du chargement simultané de `AlertEvents` et `History` → configurer `UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery)` ou `.AsSplitQuery()` en **M9**.
2. **Documentation XML (`CS1591`)** actuellement masquée globalement dans `Directory.Build.props` → activer `GenerateDocumentationFile` et documenter les API publiques en **M12**.
3. **Tests de non-fuite de contenu** : vérifiés en v1 sur `ClipboardAnalyzer` et `TypingRhythmAnalyzer`, mais pas encore en test global inspectant l'ensemble des `SecurityEvent` stockés en SQLite → ajouter un test d'invariants de confidentialité global en **M10**.
4. **Dépendances & vulnérabilités** : audit systématique (`dotnet list package --vulnerable`) et analyseurs statiques (`EnableNETAnalyzers`, `AnalysisLevel=latest-recommended`) à activer en **M9**.
5. **Corpus d'évaluation bénin** : v1 rejoue 219 événements (~9 h simulées) ; étendre à un jeu réaliste couvrant **24 h complètes** d'activité normale en **M10**.
6. **Versionnage sémantique** : passer `<Version>2.0.0</Version>` dans `Directory.Build.props` pour la v2.

---

## 4. Architecture cible v2 et nouveaux projets

| Nouveau projet | Dépendances principales (licences vérifiées) | Mission |
|---|---|---|
| `src/Sentinel.Detection.Sigma` | `YamlDotNet 18.1.0` (MIT) | M2 — Moteur Sigma YAML natif C# |
| `src/Sentinel.Detection.Static` | `PeNet 6.1.2` (Apache-2.0), `dnYara 2.1.0` (Apache-2.0 / libyara BSD-3-Clause) + moteur de repli géré explicite | M3 — YARA & analyse statique PE |
| `src/Sentinel.ThreatIntel` | `Polly 8.9.1` (BSD-3-Clause), `Microsoft.Extensions.Http.Resilience 10.11.1` (MIT), `Microsoft.Data.Sqlite` (MIT) | M4 — Renseignement sur les menaces + Bloom + SQLite |
| `src/Sentinel.ML` & `src/Sentinel.ML.Trainer` | `Microsoft.ML 5.0.1` (MIT), `Microsoft.ML.FastTree 5.0.1` (MIT), `PeNet 6.1.2` (Apache-2.0) | M5 — Extraction features EMBER & classifieur PE |
| `src/Sentinel.Installer.Msi` | `WixToolset.Sdk 5.0.2` (MS-RL) | M13 — Package MSI Windows + `build/build.ps1` + `build/sign.ps1` |
| `tests/Sentinel.Detection.Tests` | `xUnit`, `FluentAssertions` | Tests unitaires & benchmarks M2, M3, M4, M5 |

### Modèle Ollama local (`qwen2.5-coder:3b`)
- `LlmSettings.Model` par défaut mis à jour à **`qwen2.5-coder:3b`** (léger : 1,9 Go, adapté aux machines 8–16 Go RAM).
- `OllamaAssessor` conserve le timeout 10 s, `temperature = 0`, `format = "json"`, le confinement anti-injection `<donnees_non_fiables>` et la détection automatique des modèles installés sur `http://localhost:11434`.

---

## 5. Plan détaillé des 13 missions (ordre de priorité)

Chaque mission suit strictement le cycle : branche `feature/<mission>` → implémentation + tests unitaires/intégration → `dotnet build` (0 erreur) & `dotnet test` (100 % vert) → mise à jour `CHANGELOG.md` → commit Conventional Commits → fusion `--no-ff` dans `develop`.

1. **Socle v2 (`feature/v2-foundation`)** : contrats additifs `Sentinel.Shared` (nouvelles `EventCategory` : `Defender`, `Script`, `Canary`, `StaticAnalysis`, `ThreatIntel` ; nouveaux `EventTypes`/`AttributeKeys`, défaut Ollama `qwen2.5-coder:3b`, DTOs & `ApiRoutes` v2, contributions de score), `Directory.Packages.props` v2, version `2.0.0`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CHANGELOG.md`.
2. **M1 — Defender & Sysmon (`feature/m01-defender-sysmon`)** : `DefenderCollector` (WMI `MSFT_MpThreatDetection`/`MSFT_MpThreat` + EventLog Operational + détection d'affaiblissement/exclusions/désactivation temps réel), `SysmonCollector` optionnel (sans embarquer Sysmon, statut exposé au dashboard), `EventDeduplicator` fusionnant les sources multiples, règles Core associées, tests avec fixtures JSON/XML.
3. **M2 — Moteur Sigma natif (`feature/m02-sigma-engine`)** : projet `Sentinel.Detection.Sigma` (parser YAML YamlDotNet, `logsource`, sélections/filtres, conditions `and`/`or`/`not`/`1 of`/`all of`, modificateurs `contains`/`startswith`/`endswith`/`re`/`all`/`windash`/`base64`, mapping de champs documenté, hot-reload `%ProgramData%\Sentinel\rules\sigma`, activation/exclusions, 14 règles Sigma originales + `scripts/update-sigma-rules.ps1` vers SigmaHQ DRL 1.1), ≥ 30 tests + benchmark 1 000 règles × 10 000 évts.
4. **M4 — Renseignement sur les menaces (`feature/m04-threat-intel`)** : projet `Sentinel.ThreatIntel` (clients Polly retry/timeout/circuit-breaker pour abuse.ch MalwareBazaar/ThreatFox/URLhaus/Feodo + OpenPhish/PhishTank opt-in + VirusTotal on-demand clé utilisateur, stockage SQLite indexé + filtre de Bloom, `IReputationService` < qq ms hors-ligne, service de mise à jour différentielle, intégration scoring Core + API serveur).
5. **M8 — Corrélation avancée (`feature/m08-advanced-correlation`)** : modèle probabiliste **chaîne de Markov / Bayésien** appris/initialisé sur les 7 chaînes d'attaque, graphe temporel avec arêtes horodatées, mapping MITRE ATT&CK complet par cluster, explicabilité narrative chronologique + ventilation des contributions par source (`Rules`, `Sigma`, `YARA`, `ThreatIntel`, `ML`, `LLM`, `Markov`), boucle de retour VP/FP réversible et historisée.
6. **M3 — Moteur YARA & analyse statique PE (`feature/m03-yara-static`)** : projet `Sentinel.Detection.Static` (`PeStaticAnalyzer` via PeNet : Authenticode, sections, entropie, imports suspects, packer, timestamp ; intégration `dnYara` avec fallback géré documenté si `libyara` absent ; limites taille/timeout/parallélisme/priorité basse ; règles YARA originales dans `%ProgramData%\Sentinel\rules\yara` ; scan événementiel + planifié + à la demande depuis le dashboard).
7. **M9 — Auto-protection et durcissement (`feature/m09-hardening`)** : verrouillage anti-brute-force dans `AuthService`, `DirectorySecurityHardener` (ACL NTFS `%ProgramData%\Sentinel`), `SplitQuery` EF Core, analyseurs .NET, vérification vulnérabilités NuGet, vérification Watchdog + signatures manifeste, mise à jour `docs/threat-model.md`.
8. **M5 — Classifieur ML PE (`feature/m05-ml-classifier`)** : projets `Sentinel.ML` & `Sentinel.ML.Trainer` (extracteur de features EMBER sur PE via PeNet, entraînement ML.NET FastTree, jeu synthétique de test uniquement pour CI, évaluation AUC + rappel à 0,1 % FPR, explication des features contributives, intégration signal non-décisif seul dans le scoring, rapport `docs/ml-evaluation.md`).
9. **M6 — Fichiers canari anti-ransomware (`feature/m06-canary-files`)** : `CanaryManager` dans `Sentinel.Agent` (déploiement discret de leurres réalistes, enregistrement des hashes, surveillance modification/renommage/chiffrement/suppression avec corrélation PID ETW/Sysmon, réponse critique réversible suspension→arrêt + isolement réseau du processus, option activable dans paramètres/installeur, test de simulation bénin).
10. **M7 — Visibilité des scripts (`feature/m07-script-visibility`)** : `ScriptVisibilityCollector` dans `Sentinel.Agent` (EventLog `Microsoft-Windows-PowerShell/Operational` ID 4104 + ETW `Microsoft-Antimalware-Scan-Interface` sans aucun pilote AMSI managé ; détection commandes encodées, download+exec, obfuscation, contournement logging ; stockage métadonnées/hash/indicateurs + extrait nettoyé désactivable ; helper/bouton d'activation ScriptBlockLogging avec consentement).
11. **M10 — Évaluation reproductible (`feature/m10-evaluation`)** : enrichissement `Sentinel.Simulation` (scénarios bénins étendus dont Defender/Sysmon/Canari/PowerShell 4104/Sigma/YARA/TI/ML + corpus bénin 24 h, test automatisé de non-fuite de contenu dans les événements stockés, script VM-only Atomic Red Team + snapshot, génération de `docs/evaluation-report.md` honnête avec tableaux/limites/échecs éventuels).
12. **M11 — Dashboard v2 (`feature/m11-dashboard-v2`)** : nouvelles pages Blazor (**Renseignement**, **Règles Sigma/YARA**, **Modèle ML**, **Canaris**, **Santé agent**), enrichissement Graphe (filtre tactique MITRE, récit chronologique, ventilation contributions, bouton **Annuler l'action**), scan à la demande, localisation **FR / EN** (bascule langue), accessibilité de base (`aria-*`, labels associés).
13. **M12 — Documentation complète (`feature/m12-documentation`)** : mise à jour/création de tous les documents (`README.md`, `architecture.md`, `threat-model.md`, `privacy-and-consent.md`, `decision-matrix.md`, `correlation-rules.md`, `detection-sources.md`, `ml-evaluation.md`, `evaluation-report.md`, `test-plan.md`, `admin-guide.md`, `user-guide.md`, `install-guide.md`, `limitations.md`, `CHANGELOG.md`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, commentaires XML publics).
14. **M13 — Setup et installateur MSI WiX v5 (`feature/m13-installer-wix`)** : projet WiX v5 `src/Sentinel.Installer.Msi`, détection Ollama (`qwen2.5-coder:3b` / RAM), détection Defender/Sysmon avec avertissement si Defender inactif, ACL `%ProgramData%\Sentinel`, règles pare-feu locales, mise à jour majeure sur place + désinstallation propre avec choix données, `build/sign.ps1`, `build/build.ps1`, CI artifacts sur tag, `docs/install-guide.md`, puis rédaction finale de **`docs/v2-final-report.md`**.

---

## 6. Risques connus et stratégie d'atténuation

- **Environnement de développement (sans VM isolée ni privilèges `SYSTEM` permanents)** : les tests Atomic Red Team et les tests d'installation silencieuse `msiexec /qn` sur Windows 11 vierge ne doivent pas être exécutés sur le poste de développement ; les scripts et procédures de validation VM seront livrés et documentés honnêtement dans `docs/evaluation-report.md`, `docs/install-guide.md` et `docs/v2-final-report.md`.
- **Intégration native `dnYara` / `libyara`** : testée lors de M3 ; en cas d'incompatibilité binaire native sur `.NET 10 win-x64`, l'écart sera documenté explicitement et le moteur géré de repli couvrira les règles YARA de démonstration de manière transparente.
- **Clés API externes (abuse.ch, VirusTotal, PhishTank)** : aucune clé en dur ; lecture via `dotnet user-secrets` / DPAPI / variables d'environnement, fonctionnement 100 % hors-ligne garanti.
