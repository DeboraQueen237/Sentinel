# SENTINEL v2.0.0 — Rapport final de réalisation

> **Date** : 23 novembre 2026  
> **Branche d'intégration** : `develop` (13 missions + correctifs développés sur branches `feature/*` dédiées, fusionnées `--no-ff` avec Conventional Commits)  
> **Solution** : `Sentinel.slnx` (**21 projets** .NET 10 LTS + projet MSI WiX v5 `src/Sentinel.Installer.Msi`)  
> **Modèle Ollama local cible** : `qwen2.5-coder:3b` (`f72c60cabf62`, 1,9 Go)  
> **Qualité finale vérifiée** : `dotnet build` **0 erreur / 0 avertissement** (Debug & Release, `<AnalysisModeSecurity>All</AnalysisModeSecurity>`), `dotnet test` **179 / 179 verts**, **0 vulnérabilité NuGet connue** sur les 21 projets.

---

## 1. Synthèse par mission (M1 à M13)

| Mission | Branche fusionnée | Livrables principaux | Tests / Vérification | Statut |
|---|---|---|---|---|
| **Préambule** | `feature/v2-foundation` | Audit complet v1 → v2 ([v2-plan.md](v2-plan.md)), [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), [SECURITY.md](../SECURITY.md), [CHANGELOG.md](../CHANGELOG.md), épinglage `System.Security.Cryptography.Pkcs 10.0.15`, `qwen2.5-coder:3b` par défaut | Build 21 projets vert, 0 CVE NuGet | **Terminé** |
| **M1 — Defender, Sysmon & dédoublonnage** | `feature/m01-defender-sysmon` | `DefenderCollector` (WMI `MSFT_Mp*` + `Windows Defender/Operational` + affaiblissement), `SysmonCollector` optionnel (jamais embarqué), `EventDeduplicator` multi-sources, règles `RuleEngine` v2 | `DefenderSysmonDeduplicationTests` (inclus dans 37/37 `Agent.Tests`) | **Terminé** |
| **M2 — Moteur Sigma natif C#** | `feature/m02-sigma-engine` | `Sentinel.Detection.Sigma` (`YamlDotNet`, AST conditions, modificateurs `contains`/`startswith`/`endswith`/`re`/`all`/`windash`/`base64`, Aho-Corasick, hot-reload), 14 règles MIT (`rules/sigma/`), `scripts/update-sigma-rules.ps1` (SigmaHQ DRL 1.1) | 42 méthodes / 55 cas + benchmark 1 000×10 000 en **~4 s** | **Terminé** |
| **M3 — YARA & analyse statique PE** | `feature/m03-yara-static` | `Sentinel.Detection.Static` (`dnYara` protégé par `NativeLibrary.TryLoad` + `ManagedYaraFallbackEngine`, `PeNet 6.1.2`), 9 règles YARA MIT (`rules/yara/`), `StaticScanCollector` événementiel + planifié + scan à la demande, limites strictes | 15/15 `StaticAnalysisTests` verts *(voir §2 pour `libyara.dll`)* | **Terminé** *(écart documenté)* |
| **M4 — Threat Intelligence locale** | `feature/m04-threat-intel` | `Sentinel.ThreatIntel` : Polly v8 (retry/timeout/circuit-breaker), abuse.ch (4 flux CC0), OpenPhish/PhishTank opt-in, VirusTotal on-demand hash-only, SQLite indexé + filtre de Bloom, 100 % hors-ligne | `ThreatIntelTests` verts (Bloom `< 0,5 ms`, SQLite `< 2 ms` moy.) | **Terminé** |
| **M5 — Classifieur ML PE (ML.NET)** | `feature/m05-ml-pe-classifier` | `Sentinel.ML` (51 features EMBER-like via `PeNet`, FastTree + Platt, score plafonné ≤ 35/100, explicabilité `CalculateFeatureContribution`), CLI `Sentinel.ML.Trainer`, [ml-evaluation.md](ml-evaluation.md) | `MlClassifierTests` verts ; CLI 10k synthétique : AUC `0,9995`, Recall@0,1%FPR `96,1 %` | **Terminé** *(synthétique CI)* |
| **M6 — Fichiers canari anti-ransomware** | `feature/m06-anti-ransomware-canaries` | `CanaryManager` & `CanaryCollector` (fichiers leurres discrets + SHA-256, détection modif/renommage/chiffrement/suppression → réponse critique réversible) | `CanaryManagerTests` (inclus dans 37/37 `Agent.Tests`) | **Terminé** |
| **M7 — Visibilité scripts sans AMSI managé** | `feature/m07-script-visibility` | `ScriptVisibilityCollector` (PowerShell Event ID `4104` + ETW AMSI lecture seule, métadonnées/hash par défaut, extrait opt-in ≤ 300 car. caviardé), `scripts/enable-script-logging.ps1` | `ScriptVisibilityTests` (inclus dans 37/37 `Agent.Tests`) | **Terminé** |
| **M8 — Corrélation avancée & fusion** | `feature/m08-advanced-correlation` | `AttackChainMarkovModel` (priors v1+v2), feedback VP/FP historisé et réversible (`RevertFeedback`), arêtes horodatées, `ClusterNarrativeBuilder`, tactiques MITRE, `ScoreContributions`, escalade au 2ᵉ événement préservée | `AdvancedCorrelationTests` (inclus dans 37/37 `Core.Tests`) | **Terminé** |
| **M9 — Auto-protection & durcissement** | `feature/m09-hardening-and-v2-api` + `fix/m09-acl-non-elevated-safety` | Verrouillage brute-force admin (5 échecs → 15 min, HTTP `429`), `DirectorySecurityHardener` (NTFS `SYSTEM`+`Admins` en mode élevé/service), `.AsSplitQuery()`, Watchdog détection suppression service, APIs v2, `AnalysisModeSecurity=All`, 0 CVE NuGet | 14/14 `Server.Tests` verts dont **inspection vie privée SQLite** | **Terminé** |
| **M10 — Évaluation reproductible** | `feature/m10-evaluation` | 11 scénarios (v1+v2) + 459 évts bénins / 24 h (`Sentinel.Simulation`), benchmark déterministe + Ollama réel `qwen2.5-coder:3b`, `scripts/run-atomic-red-team-vm.ps1` (VM-only), [evaluation-report.md](evaluation-report.md) | **-55,0 % TTD** (`13,55 s → 6,09 s`), **0,00 % FPR**, 100 % 2ᵉ év. | **Terminé** |
| **M11 — Dashboard v2 Blazor** | `feature/m11-dashboard-v2` | 5 nouveaux écrans (`/intel`, `/rules`, `/ml`, `/canaries`, `/health`), graphe enrichi (filtre tactique MITRE, récit, contributions moteurs, Annuler 1 clic), bilingue FR/EN, clair/sombre | Vérifié en direct dans Chrome : **0 erreur console, 0 HTTP ≥ 400** | **Terminé** |
| **M12 — Documentation synchronisée** | `feature/m12-documentation` | `README.md`, 11 docs `docs/*.md` synchronisées, `CHANGELOG.md`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, génération XML doc sur les bibliothèques | Build 0 avertissement / 0 erreur | **Terminé** |
| **M13 — Installateur Windows x64 & MSI WiX v5** | `feature/m13-installer-wix` | `Sentinel.Installer` v2 (diagnostics Defender/Sysmon/Ollama+RAM, ACL, pare-feu, règles, `--delete-data`), projet MSI WiX v5 (`src/Sentinel.Installer.Msi`), `build/build.ps1`, `build/sign.ps1`, CI release tags `v*` | `SentinelPortable-2.0.0.zip` (150,7 Mo) + `SHA256SUMS.txt` vérifiés *(voir §2 pour compilation MSI locale)* | **Terminé** *(écart réseau documenté)* |

---

## 2. Écarts documentés et alternatives mises en place (transparence totale)

Conformément aux règles non négociables, aucun point risqué ou impossible n'a été contourné en silence :

1. **Bibliothèque native `libyara.dll` absente du package NuGet `dnYara 2.1.0` (M3)** :
   - *Constat* : `dnYara` ne redistribue pas la DLL native `libyara.dll` ; de plus, instancier `new YaraContext()` en son absence provoquait un plantage fatal dans le finaliseur GC (`~YaraContext → yr_finalize`).
   - *Mesure prise* : sonde préalable via `NativeLibrary.TryLoad("libyara")` avant toute instanciation de `YaraContext` + bascule transparente et explicitement tracée (`ManagedFallback (libyara indisponible)`) vers `ManagedYaraFallbackEngine`, complété par `PeStaticAnalyzer` (`PeNet 6.1.2`). Si l'opérateur dépose `libyara.dll` (x64) à côté des binaires, `dnYara` natif est activé automatiquement.
2. **Compilation locale du `.msi` WiX v5 bloquée par le débit réseau du poste de dev (M13)** :
   - *Constat* : WiX Toolset n'est pas préinstallé sur ce poste, et le téléchargement de `WixToolset.Sdk 5.0.2` (20 Mo) depuis `api.nuget.org` a plafonné à ~6 Ko/s (timeout après 2 min, > 50 min estimées).
   - *Mesure prise* :
     - `dist/SentinelPortable-2.0.0.zip` (**150,7 Mo**, SHA-256 `8ac8ee62e857b433cd482731447544dd333ad0e49a338dba78036081405d0586`) incluant les 6 composants Release x64 + l'assistant `Sentinel.Installer.exe` v2.0.0 + `rules/` + `extension/` a été généré et vérifié localement.
     - Le projet WiX v5 complet (`src/Sentinel.Installer.Msi/Sentinel.Installer.Msi.wixproj`, `Package.wxs`, `License.rtf`) et `build/build.ps1` sont prêts et branchés sur le workflow GitHub Actions `.github/workflows/ci.yml` (job `package-release` sur tags `v*` / `workflow_dispatch`, exécuté sur `windows-latest` haut débit pour produire `SentinelSetup-2.0.0.msi`, `SentinelPortable-2.0.0.zip` et `SHA256SUMS.txt`).
3. **Latence CPU d'Ollama `qwen2.5-coder:3b` (M10)** :
   - *Constat* : lors de l'exécution live contre `qwen2.5-coder:3b` sur CPU (sans GPU dédié), la majorité des requêtes de la bande ambiguë a dépassé 30 s, déclenchant le repli déterministe automatique.
   - *Résultat* : `11/11` détections, `0,00 %` FPR et **`-55,0 %` TTD** maintenus grâce à Sigma + corrélation Markovienne. Recommandation : utiliser un GPU local ou un modèle quantifié plus compact (`qwen2.5-coder:1.5b` préchauffé) pour un enrichissement LLM temps réel `< 3 s`.
4. **Tests VM non exécutés sur la machine de développement (M10, M13)** :
   - Les scénarios Atomic Red Team (`scripts/run-atomic-red-team-vm.ps1`) et le cycle complet `msiexec /i /qn` → mise à niveau → `msiexec /x /qn` sur VM Windows 11 vierge n'ont pas été exécutés sur le poste de développement afin de préserver son intégrité ; ils sont prêts à être exécutés par l'opérateur dans une VM isolée avec snapshot.
5. **Dataset EMBER non commité (M5)** :
   - Les données EMBER 2018 ne sont jamais commitées dans Git. Le jeu synthétique sert uniquement aux tests CI ; la commande directe d'entraînement légal `--ember-jsonl` est implémentée et documentée dans [ml-evaluation.md](ml-evaluation.md).

---

## 3. Résultats clés d'évaluation scientifique

| Métrique | (A) Règles + Sigma | (B) + IA déterministe | (B') + Ollama réel `qwen2.5-coder:3b` | (C) SENTINEL v2 Complet |
|---|---:|---:|---:|---:|
| Scénarios détectés (v1 + v2) | 11 / 11 (100 %) | 11 / 11 (100 %) | 11 / 11 (100 %) | **11 / 11 (100 %)** |
| Faux positifs (459 évts / 24 h) | 0 (**0,00 %**) | 0 (**0,00 %**) | 0 (**0,00 %**) | **0 (0,00 %)** |
| Événements moy. avant alerte | 2,64 | 2,27 | 2,64 | **1,73** (`-0,91`) |
| Time-To-Detect moyen | 13,55 s | 10,45 s | 13,55 s | **6,09 s (`-55,0 %`)** |
| Escalade au 2ᵉ événement | — | — | — | **100 % (moy. 1,80 év.)** |
| Latence pipeline moyenne | 0,12 ms | 0,03 ms | 595,84 ms *(timeouts CPU)* | **0,05 ms** *(déterm.)* / 710,61 ms *(CPU)* |

---

## 4. Licences tierces à vérifier avant toute diffusion commerciale

Voir le tableau complet dans [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) :
- **`QuestPDF 2026.9.2`** : *Community License* (gratuit/MIT-compatible sous 1 M$ USD de chiffre d'affaires annuel ou usage académique/open-source ; licence commerciale requise au-delà).
- **`SigmaHQ Rules`** : *DRL 1.1* (non embarqué, téléchargé en option par l'utilisateur).
- **`OpenPhish Community`** : *usage non commercial uniquement* (désactivé par défaut, opt-in explicite).
- **`Sysmon` (Microsoft Sysinternals)** : *redistribution interdite* (jamais embarqué, uniquement détecté).
- **`FluentAssertions 7.2.0`** : volontairement épinglé en `7.2.0` (dernière version Apache-2.0, test-only).

---

## 5. Dette technique résiduelle et pistes pour SENTINEL v3

1. **Validation MSI & Atomic Red Team sur VM Windows 11 vierge** : déclencher le workflow `package-release` (GitHub Actions) sur un tag `v2.0.0`, puis valider `msiexec /i SentinelSetup-2.0.0.msi /qn`, mise à niveau `2.0.1` et `msiexec /x` + `run-atomic-red-team-vm.ps1` dans une VM isolée.
2. **Packaging optionnel de `libyara.dll` x64** : documenter ou fournir un script de téléchargement vérifié par SHA-256 de `libyara.dll` (BSD-3-Clause) pour activer les modules natifs YARA (`pe.*`, `math.*`).
3. **Modèle ML entraîné sur EMBER 2018 / SOREL-20M** : publier un artefact versionné entraîné hors dépôt sur corpus réel (jamais dans Git) et ajouter un suivi périodique de dérive (*concept drift*).
4. **Migration PostgreSQL multi-postes & authentification multi-analystes RBAC** : le modèle EF Core étant déjà compatible PostgreSQL, une v3 orientée parc PME pourrait séparer les rôles *Lecteur SOC* / *Analyste* / *Administrateur* et déployer `Sentinel.Server` sur un hôte dédié.
5. **Préchauffage / quantisation LLM** : ajouter une option `keep_alive` et une file d'enrichissement asynchrone en arrière-plan pour que les appels LLM CPU ne ralentissent jamais le flux temps réel des événements.
