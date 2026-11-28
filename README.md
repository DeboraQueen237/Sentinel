# SENTINEL v2

**Agent léger de détection et de prévention des menaces (EDR) pour Windows — Défense en profondeur multi-moteurs, corrélation Markovienne et IA 100 % locale**

[![.NET 10](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Version](https://img.shields.io/badge/Version-2.2.0-10B981)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/Plateforme-Windows%2010%2F11%20x64-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/Licence-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions)](.github/workflows/ci.yml)

---

## Présentation

**SENTINEL v2** complète Microsoft Defender sur un poste Windows x64 en combinant **8 moteurs de détection locaux complémentaires**, un **moteur de corrélation contextuelle Markovien** (reliant les signaux faibles en chaînes MITRE ATT&CK), une **IA 100 % locale (Ollama, défaut `qwen2.5-coder:3b`)** et une **réponse graduée réversible en un clic**.

> **Résultat scientifique mesuré (v2 — 11 scénarios + 24 h bénin / 459 événements)** : la corrélation contextuelle réduit le délai de détection (**Time-To-Detect**) de **-55,0 %** (`13,55 s → 6,09 s`, `-0,91` événement en moyenne) avec **0,00 % de faux positifs** et une escalade dès le **2ᵉ événement** sur 100 % des chaînes multi-étapes — y compris en conditions réelles avec Ollama local `qwen2.5-coder:3b`. Voir [docs/evaluation-report.md](docs/evaluation-report.md).

### Nouveautés majeures de la v2

- **Appui natif sur Microsoft Defender & Sysmon optionnel (M1)** : collecte WMI + journal `Windows Defender/Operational` (détections + affaiblissement : exclusions, protection temps réel désactivée, arrêt service), détection automatique de Sysmon (jamais embarqué), dédoublonnage multi-sources.
- **Moteur Sigma natif en C# (M2)** : parseur YAML (`YamlDotNet`), sélections/filtres/conditions/modificateurs (`contains`, `startswith`, `endswith`, `re`, `all`, `windash`, `base64`), 14 règles MIT incluses + script de mise à jour SigmaHQ (`DRL 1.1`), benchmark 1 000 règles × 10 000 événements en ~4 s.
- **Moteur YARA + Analyse statique PE (M3)** : intégration `dnYara` avec repli managé transparent (`ManagedYaraFallbackEngine` si `libyara.dll` absente), analyse PE `PeNet` (Authenticode, entropie par section, imports suspects, packers, horodatage), scan événementiel + planifié + à la demande, limites strictes de ressources.
- **Threat Intelligence locale hors-ligne (M4)** : clients HTTP résilients Polly v8 (abuse.ch MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker en CC0 ; OpenPhish/PhishTank opt-in ; VirusTotal strictement à la demande par hash), stockage SQLite indexé + filtre de Bloom (`< 2 ms` hors-ligne).
- **Classifieur ML de fichiers PE (M5)** : 51 caractéristiques EMBER-like (`PeNet`) + ML.NET FastTree (`Sentinel.ML` + CLI `Sentinel.ML.Trainer`), score strictement borné (≤ 35/100, **jamais seul décisif**), explicabilité locale (`CalculateFeatureContribution`).
- **Fichiers canari anti-ransomware (M6)** : déploiement discret de fichiers leurres avec empreintes SHA-256 ; toute modification, renommage, chiffrement ou suppression déclenche immédiatement une réponse critique réversible.
- **Visibilité scripts sans fournisseur AMSI managé (M7)** : PowerShell Script Block Logging Event ID `4104` + ETW `Microsoft-Antimalware-Scan-Interface` optionnel, métadonnées/hash/indicateurs par défaut (extrait tronqué avec caviardage automatique des secrets désactivé par défaut).
- **Corrélation avancée & gouvernance (M8–M9)** : modèle de transitions de Markov, feedback VP/FP historisé et réversible, arêtes horodatées, récit chronologique, ventilation des contributions par moteur, verrouillage anti brute-force admin (HTTP 429), ACL NTFS restrictives (`SYSTEM` + `Administrateurs`), Watchdog avec détection de suppression de service.
- **Console Blazor v2.2 bilingue FR/EN (M11 + v2.2)** : 14 écrans complets incluant l'**Arbre causal & Flux chronologique temps réel** (`/graph` avec distinction flux directs `──▶` vs indirects `- -▶` et déduplication `×N`), l'écran **Scan Système Général, Audit 11 points & Démo Live** (`/scan-audit`), les **diagnostics d'incident IA Qwen** à la demande, et les **notifications In-App (cloche temps réel) + SMS + WhatsApp + Email + Webhooks** chiffrées par DPAPI.
- **Installateur Windows x64 professionnel (M13)** : package **MSI WiX v5** (`SentinelSetup-2.2.0.msi`), archive portable (`SentinelPortable-2.2.0.zip`), script de mise à niveau des services existants (`scripts/upgrade-installed-services.ps1`), assistant graphique avec consentement explicite et scripts `build/build.ps1` / `build/sign.ps1`.

---

## Prérequis

| Composant | Détail | Obligatoire |
|---|---|---|
| **Système** | Windows 10 / 11 (x64) | Oui |
| **.NET** | **.NET 10 SDK** (pour compilation depuis les sources) ou **MSI autonome / portable** | Pour dev / build |
| **Microsoft Defender** | Maintenu actif (SENTINEL complète Defender, ne le remplace pas) | Recommandé |
| **Ollama (local)** | Instance locale `http://localhost:11434` — modèle par défaut **`qwen2.5-coder:3b`** (1,9 Go, compatible 8–16 Go RAM) | Optionnel *(repli déterministe automatique)* |
| **Sysmon** | Optionnel, jamais embarqué ; automatiquement détecté s'il est installé | Optionnel |

---

## Démarrage rapide

### 1. Compilation et tests (21 projets, 179 tests)

```powershell
dotnet restore Sentinel.slnx
dotnet build Sentinel.slnx --no-restore
dotnet test Sentinel.slnx --no-build
```

### 2. Lancement en développement (avec données de démonstration)

```powershell
# Démarre Sentinel.Server (:5180/:5181) + Sentinel.Admin (:5200) + démonstration multi-postes
.\scripts\run-dev.ps1 -SeedDemo

# Ouvrez ensuite http://127.0.0.1:5200 dans votre navigateur
```

### 3. Lancer l'évaluation scientifique A vs B vs C

```powershell
# Benchmark déterministe (CI)
dotnet run --project tests/Sentinel.Simulation -- --output-md docs/evaluation-results.md --output-json docs/evaluation-results.json

# Benchmark réel avec votre Ollama local (qwen2.5-coder:3b)
dotnet run --project tests/Sentinel.Simulation -- --ollama --ollama-url http://localhost:11434 --ollama-model qwen2.5-coder:3b
```

### 4. Construire le MSI WiX v5 et l'archive portable

```powershell
# Restore + Release build + Tests + Publication win-x64 + MSI WiX v5 + Portable ZIP + SHA256SUMS.txt
.\build\build.ps1
```

Les livrables sont produits dans `dist/` :
- `dist/SentinelSetup-2.2.0.msi` (installateur Windows MSI WiX v5)
- `dist/SentinelPortable-2.2.0.zip` (archive portable x64)
- `dist/SHA256SUMS.txt` (empreintes SHA-256 vérifiables)

> **Mise à niveau d'une installation existante (`v1.0.0` / `v2.0.0` → `v2.2.0`)** : exécutez `.\scripts\upgrade-installed-services.ps1` (invite UAC Administrateur) pour mettre à jour les binaires de `C:\Program Files\Sentinel\` et redémarrer proprement les 4 services Windows.

---

## Documentation complète (`docs/`)

| Document | Contenu |
|---|---|
| [docs/presentation-et-demo.md](docs/presentation-et-demo.md) | **Plan de soutenance chronométré (10–15 min), scénarios de démonstration live et tests jury** |
| [docs/guide-utilisation-et-tests.md](docs/guide-utilisation-et-tests.md) | Guide complet d'utilisation, configuration notifications (In-App/SMS/WhatsApp/Email) et recette |
| [docs/architecture.md](docs/architecture.md) | Architecture globale v2 (21 projets), diagrammes Mermaid, flux gRPC/IPC/SignalR, schéma BDD & disques |
| [docs/detection-sources.md](docs/detection-sources.md) | Sources v2 : Defender, Sysmon, Sigma (table de mapping), YARA/PE, Threat Intel, ML PE, Canaris, PowerShell 4104 |
| [docs/correlation-rules.md](docs/correlation-rules.md) | Graphe temporel, modèle de Markov, escalade au 2ᵉ événement, chaînes MITRE ATT&CK, feedback réversible |
| [docs/decision-matrix.md](docs/decision-matrix.md) | Matrice de décision déterministe (niveaux 0–4), réversibilité en 1 clic, anti-faux-positifs |
| [docs/privacy-and-consent.md](docs/privacy-and-consent.md) | Liste fermée de collecte, exclusions absolues, notice de consentement, rétention, audit |
| [docs/threat-model.md](docs/threat-model.md) | Analyse STRIDE v2, durcissement (lockout 429, ACL NTFS, Watchdog, anti-prompt-injection) |
| [docs/evaluation-report.md](docs/evaluation-report.md) | Rapport scientifique v2 (11 scénarios + 24 h bénin, déterministe & Ollama réel `qwen2.5-coder:3b`) |
| [docs/ml-evaluation.md](docs/ml-evaluation.md) | Classifieur ML PE (51 features EMBER-like, métriques, obtention légale EMBER, limites) |
| [docs/install-guide.md](docs/install-guide.md) | Guide d'installation (MSI, Setup WinForms, portable, Ollama, Defender/Sysmon, désinstallation) |
| [docs/admin-guide.md](docs/admin-guide.md) | Guide administrateur SOC (13 écrans, règles, renseignement, canaris, annulation d'actions, audit) |
| [docs/user-guide.md](docs/user-guide.md) | Guide utilisateur poste (icône Tray, confidentialité, modes, notifications) |
| [docs/limitations.md](docs/limitations.md) | Limites assumées, écarts connus et recommandations de déploiement |
| [docs/test-plan.md](docs/test-plan.md) | Plan de test complet, scénarios v1/v2 et protocole VM Atomic Red Team |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Inventaire complet des licences (NuGet, JS, règles, flux TI, outils) |
| [SECURITY.md](SECURITY.md) | Politique de sécurité et signalement de vulnérabilités |
| [CHANGELOG.md](CHANGELOG.md) | Historique détaillé des versions (`1.0.0` → `2.0.0`) |

---

## Éthique, vie privée et licence

- **Défensif uniquement** : aucun malware, exploit, keylogger ni outil offensif.
- **Vie privée vérifiée automatiquement** : aucune frappe clavier, aucun contenu de document ou de messagerie stocké (vérifié par inspection SQLite automatisée dans `Sentinel.Server.Tests`).
- **Licence** : distribué sous licence **MIT** — voir [LICENSE](LICENSE) et [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
