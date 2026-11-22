# SENTINEL

**Agent léger de détection et de prévention des menaces (EDR) avec moteur de corrélation contextuelle et IA 100 % locale**

[![.NET 10](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Plateforme-Windows%2010%2F11-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/Licence-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions)](.github/workflows/ci.yml)

---

## Présentation

**SENTINEL** surveille un poste Windows en continu, attribue à chaque événement technique un score de menace justifié (**règles déterministes + baseline comportementale + LLM local Ollama**), relie les **signaux faibles** dans un graphe de corrélation en temps réel et déclenche une **réponse graduée et réversible en un clic**.

> **Hypothèse scientifique démontrée** : *la corrélation d'événements individuellement faibles réduit significativement le délai de détection (Time-To-Detect) d'une chaîne d'attaque par rapport à une analyse événement par événement, à taux de faux positifs comparable — avec escalade précoce dès le 2ᵉ événement similaire dans un même contexte.*

### Points forts

- **100 % local et respectueux de la vie privée** : IA exécutée localement via Ollama, aucune donnée envoyée sur Internet, **aucun keylogger**, aucun contenu de documents ni de messageries collecté.
- **Moteur de corrélation en graphe** : fenêtres glissantes (5 min / 30 min / 24 h), décroissance exponentielle, **7 chaînes d'attaque modélisées** (Phishing, BadUSB, Ransomware, Exfiltration, Brute force, Persistance, Ingénierie sociale) mappées à **MITRE ATT&CK**.
- **Décision graduée & réversible** : niveaux 0–4, mode apprentissage 7 jours, mode simulation, tickets d'action réversibles en un clic (quarantaine chiffrée, règles pare-feu, hosts, PnP).
- **Sécurité intégrée** : communication agent ↔ serveur en **gRPC mTLS** (PKI locale ECDSA P-256), secrets protégés par **DPAPI**, authentification admin **PBKDF2 + 2FA TOTP**, journaux d'événements et d'audit **chaînés en SHA-256** vérifiables, service **Watchdog** d'auto-protection.
- **Console Blazor Server temps réel** : 8 écrans complets avec graphe interactif **Cytoscape.js** et graphiques **Chart.js** embarqués en local (zéro CDN).

---

## Architecture synthétique

```text
Session Utilisateur             Services Windows (LocalSystem)           Serveur & Console
───────────────────             ──────────────────────────────           ─────────────────
extension/ (MV3) ──► BrowserHost ─┐                                      Sentinel.Server
Sentinel.Tray (Clipboard, Frappe) ┼─► Named Pipe ─► Sentinel.Agent ──► gRPC mTLS (:5181)
                                                    (Outbox SQLite)       ├─ Sentinel.Core (Pipeline)
                                Sentinel.Watchdog ◄─► Auto-protection     ├─ Sentinel.AI ◄─► Ollama (:11434)
                                                                          ├─ Sentinel.Storage (SQLite WAL)
                                                                          └─ REST + SignalR (:5180)
                                                                                    ▲
                                                                                    ▼
                                                                          Sentinel.Admin (Blazor :5200)
```

Pour l'architecture détaillée (diagrammes Mermaid, flux gRPC/IPC/SignalR et schéma relationnel complet), voir [docs/architecture.md](docs/architecture.md).

---

## Prérequis

| Composant | Version / Détail | Obligatoire |
|---|---|---|
| **OS** | Windows 10 / 11 (64 bits) | Oui |
| **.NET SDK** | **.NET 10 SDK** (10.0 LTS) | Oui |
| **Ollama** | Instance locale sur `http://localhost:11434` (`qwen2.5:7b` sur 16 Go RAM, `qwen2.5:3b` ou `phi3:mini` sur 8 Go RAM ; `nomic-embed-text` optionnel) | Optionnel *(repli automatique sur les règles déterministes si indisponible)* |
| **Droits administrateur** | Requis pour l'installation des services Windows et la collecte ETW complète | Pour le déploiement service |

---

## Démarrage rapide

### 1. Compilation et tests

```powershell
dotnet restore Sentinel.slnx
dotnet build Sentinel.slnx --no-restore
dotnet test Sentinel.slnx --no-restore
```

### 2. Lancement en mode développement (sans installer les services Windows)

Le script PowerShell dédié démarre automatiquement le serveur, la console Blazor et (en option) injecte des scénarios de démonstration réalistes en direct via gRPC :

```powershell
# Démarrage rapide (Serveur + Console Admin + démonstration multi-postes pré-remplie)
.\scripts\run-dev.ps1 -SeedDemo

# Ou avec l'agent système local et l'icône de notification
.\scripts\run-dev.ps1 -WithAgent -WithTray
```

Vous pouvez aussi lancer chaque processus manuellement avec `SENTINEL_DATA_DIR` pour isoler les données de développement (base SQLite, certificats mTLS, secrets DPAPI, journaux) :

```powershell
$env:SENTINEL_DATA_DIR = "$PWD\.sentinel-dev"

# Terminal 1 — Serveur d'analyse (REST/SignalR :5180, gRPC mTLS :5181)
dotnet run --project src/Sentinel.Server/Sentinel.Server.csproj

# Terminal 2 — Console d'administration Blazor (http://127.0.0.1:5200)
dotnet run --project src/Sentinel.Admin/Sentinel.Admin.csproj

# Terminal 3 — Agent de collecte
dotnet run --project src/Sentinel.Agent/Sentinel.Agent.csproj

# Terminal 4 (optionnel) — Compagnon barre système (presse-papiers, rythme de frappe, notifications)
dotnet run --project src/Sentinel.Tray/Sentinel.Tray.csproj
```

Ouvrez ensuite `http://127.0.0.1:5200` dans votre navigateur pour créer le compte administrateur initial (mot de passe + QR code **2FA TOTP**).

### 3. Activer le scoring IA local (Ollama, optionnel)

```powershell
ollama pull qwen2.5:7b
ollama serve
```

### 4. Construction du Setup et déploiement en services Windows

Générez le package d'installation autonome (`dist/Sentinel-Setup-v1.0.0/` et `dist/Sentinel-Setup-v1.0.0.zip`) puis lancez l'assistant graphique (droits administrateur pour les services Windows) :

```powershell
# Générer le Setup complet (inclut Server, Admin, Agent, Watchdog, Tray, BrowserHost, extension/)
.\scripts\build-installer.ps1

# Lancer l'assistant graphique (avec écran de consentement explicite)
.\dist\Sentinel-Setup-v1.0.0\Sentinel.Installer.exe

# Ou en ligne de commande (mode développeur / CI) :
dotnet run --project src/Sentinel.Installer/Sentinel.Installer.csproj
```

L'installeur déploie les 194 fichiers applicatifs, affiche l'**écran de consentement explicite** (`consent.json`), génère les certificats mTLS locaux (`SentinelPki`), calcule le manifeste d'intégrité SHA-256 (`integrity-manifest.json`), installe les services Windows (`SentinelServer`, `SentinelAdmin`, `SentinelAgent`, `SentinelWatchdog`), configure le démarrage automatique de `Sentinel.Tray` et enregistre l'hôte Native Messaging pour l'extension navigateur (`extension/`).

---

## Écrans de la console d'administration (`Sentinel.Admin`)

| # | Écran | Fonctionnalités principales |
|---|---|---|
| 1 | **Vue d'ensemble** | Score de sécurité global (0–100), alertes actives, blocages en cours, courbe des menaces 24 h / 7 j / 30 j, santé LLM/agents |
| 2 | **Alertes** | Liste filtrable, détail explicable (règles, IA, MITRE ATT&CK, événements liés), actions *Approuver / Rejeter (faux positif) / Acquitter / Résoudre* |
| 3 | **Graphe de corrélation** | Visualisation interactive **Cytoscape.js** : zoom, filtres temporels/score, inspection des nœuds et mise en évidence des clusters |
| 4 | **Fiches** | Profil par poste, utilisateur, domaine, processus, fichier, périphérique ou IP avec baseline comportementale *(consultation journalisée)* |
| 5 | **Actions & blocages** | Suivi des tickets d'action, blocages manuels et **annulation en un clic** (restauration de l'état initial) |
| 6 | **Rapports** | Export **PDF** (QuestPDF) et **JSON** des rapports de sécurité et résultats d'évaluation A/B/C |
| 7 | **Paramètres** | Seuils 0–4, mode (`Learning` / `Simulation` / `Active`), dossiers surveillés, exclusions, rétention, modèle Ollama, paramètres de corrélation |
| 8 | **Audit** | Journal chaîné SHA-256 des accès et actions administrateur + bouton de **vérification d'intégrité cryptographique** |

---

## Structure du dépôt

```text
Sentinel/
├── README.md
├── LICENSE                          # Licence MIT
├── Sentinel.slnx                    # Solution .NET 10
├── Directory.Build.props            # Propriétés communes (net10.0, Nullable)
├── Directory.Packages.props         # Gestion centralisée des versions NuGet
├── SENTINEL_Documentation.md        # Spécification de conception initiale
├── .github/workflows/ci.yml         # Pipeline CI GitHub Actions (Windows / .NET 10)
├── docs/
│   ├── architecture.md              # Architecture détaillée, flux gRPC/IPC/SignalR, schéma BDD
│   ├── privacy-and-consent.md       # Liste fermée de collecte, texte de consentement, cadre légal
│   ├── threat-model.md              # Analyse STRIDE, surfaces d'attaque et limites assumées
│   ├── correlation-rules.md         # Clés, fenêtres, formule de cluster et 7 chaînes MITRE ATT&CK
│   ├── decision-matrix.md           # Niveaux 0–4, matrice d'actions, réversibilité et anti-FP
│   ├── test-plan.md                 # Scénarios de simulation et protocole comparatif A / B / C
│   └── guide-utilisation-et-tests.md # Guide pas-à-pas d'utilisation et de test complet
├── extension/                       # Extension navigateur Manifest V3 (Chrome / Edge)
├── src/
│   ├── Sentinel.Shared/             # Contrats figés : modèles, REST/SignalR, gRPC, IPC, PKI, HashChain
│   ├── Sentinel.AI/                 # Client Ollama local, prompts encadrés, validation JSON
│   ├── Sentinel.Core/               # Pipeline d'analyse : règles, baseline, corrélation, décision
│   ├── Sentinel.Storage/            # EF Core SQLite WAL (compatible PostgreSQL), intégrité, rétention
│   ├── Sentinel.Server/             # Service central : gRPC mTLS, API REST, SignalR, PDF, auth 2FA
│   ├── Sentinel.Agent/              # Service Windows : collecteurs, outbox SQLite, exécuteur d'actions
│   ├── Sentinel.Tray/               # Compagnon session utilisateur : icône, presse-papiers, rythme de frappe
│   ├── Sentinel.BrowserHost/        # Hôte Native Messaging reliant extension/ au Named Pipe
│   ├── Sentinel.Watchdog/           # Service indépendant d'auto-protection et contrôle SHA-256
│   ├── Sentinel.Admin/              # Console d'administration Blazor Server + Cytoscape.js / Chart.js
│   └── Sentinel.Installer/          # Installeur WinForms avec écran de consentement explicite
└── tests/
    ├── Sentinel.Core.Tests/         # Tests unitaires scoring, corrélation, décision
    ├── Sentinel.Agent.Tests/        # Tests unitaires collecteurs, outbox, réversibilité
    ├── Sentinel.Server.Tests/       # Tests intégration stockage, hash-chain, API, auth
    └── Sentinel.Simulation/         # Banc de simulation des scénarios d'attaque (A vs B vs C)
```

---

## Tests et simulation d'attaque

```powershell
# Exécuter la suite complète de tests
dotnet test Sentinel.slnx --no-restore

# Exécuter le comparatif scientifique (A: Règles | B: Règles+IA | C: Règles+IA+Corrélation)
dotnet run --project tests/Sentinel.Simulation/Sentinel.Simulation.csproj
```

Voir [docs/test-plan.md](docs/test-plan.md) pour les 8 scénarios de simulation (EICAR, Phishing, BadUSB, Ransomware, Exfiltration, Brute force, Persistance, Ingénierie sociale) et les métriques (TTD, rappel, précision, FPR).

---

## Éthique, vie privée et limites assumées

- **Exclusions absolues** : aucun enregistrement de frappes clavier (pas de keylogger), aucun contenu de messageries chiffrées, aucun contenu de documents ni de formulaires web.
- **Consentement et transparence** : écran de consentement explicite avant installation, icône visible en permanence, rétention automatique (90 j événements / 12 mois alertes), audit chaîné des accès administrateur. Voir [docs/privacy-and-consent.md](docs/privacy-and-consent.md).
- **Complémentaire à votre antivirus** : SENTINEL est un **EDR léger en espace utilisateur/service** ; il ne remplace pas un antivirus à pilote noyau (**conservez Microsoft Defender actif**). Voir [docs/threat-model.md](docs/threat-model.md).

---

## Licence

Ce projet est distribué sous licence **MIT** — voir le fichier [LICENSE](LICENSE).
