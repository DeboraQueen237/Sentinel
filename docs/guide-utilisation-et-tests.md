# Guide complet d'utilisation et de test — SENTINEL

Ce guide explique comment démarrer **SENTINEL**, accéder à la console d'administration, tester chaque fonctionnalité (détection, corrélation, graphes, réponses réversibles, rapports PDF/JSON, intégrité cryptographique), exécuter les bancs de tests automatisés et déployer les services Windows ainsi que l'extension navigateur.

---

## 1. Prérequis

- **Système** : Windows 10 ou Windows 11 (64 bits).
- **SDK** : [.NET 10 SDK](https://dotnet.microsoft.com/download) (`10.0.x`).
- **IA locale (optionnelle)** : [Ollama](https://ollama.com/) sur `http://localhost:11434` avec par exemple :
  ```powershell
  ollama pull qwen2.5:7b
  ollama pull nomic-embed-text
  ```
  > Si Ollama est arrêté, SENTINEL bascule automatiquement et sans latence sur son moteur de règles déterministes + baseline comportementale.

---

## 2. Démarrage rapide de la pile complète (Développement & Démo)

Un script PowerShell tout-en-un démarre le serveur central (`Sentinel.Server`), la console web (`Sentinel.Admin`) et, en option, l'agent système, l'icône de notification et le rejeu de scénarios d'attaque multi-postes :

```powershell
# Option A : Serveur + Console Admin + Scénarios d'attaque réalistes pré-injectés (recommandé pour tester le dashboard)
.\scripts\run-dev.ps1 -SeedDemo

# Option B : Sans recompiler (si déjà compilé)
.\scripts\run-dev.ps1 -NoBuild -SeedDemo

# Option C : Avec l'agent système local et l'icône de barre des tâches (surveillance temps réel de votre poste)
.\scripts\run-dev.ps1 -WithAgent -WithTray
```

### Points d'accès locaux
- **Console d'administration Blazor** : `http://127.0.0.1:5200`
- **API REST & SignalR** : `http://127.0.0.1:5180` *(santé anonyme : `http://127.0.0.1:5180/api/system/ping`)*
- **Canal gRPC mTLS Agents** : `https://localhost:5181`
- **Données isolées (mode dev)** : `.sentinel-dev-data/` *(base SQLite WAL, certificats PKI locaux, secrets DPAPI, journaux)*

> Pour repartir d'une base vierge en mode dev, arrêtez le script (`Ctrl+C`) puis supprimez le dossier `.sentinel-dev-data/`.

---

## 3. Première connexion & Authentification 2FA TOTP

1. Ouvrez `http://127.0.0.1:5200` dans votre navigateur.
2. **S'il s'agit d'une base vierge**, vous êtes redirigé automatiquement vers `/setup` :
   - Créez le compte administrateur unique (nom d'utilisateur + mot de passe ≥ 10 caractères).
   - À l'étape 2, scannez le **QR Code TOTP** avec votre application d'authentification (Aegis, Google Authenticator, Bitwarden…) ou utilisez le bouton **« Pré-remplir le code TOTP actuel »** pour valider immédiatement en test local.
   - **Conservez la clé Base32 affichée** pour vos reconnexions ultérieures.
3. **Pour les connexions suivantes** (`/login`) :
   - Saisissez identifiant, mot de passe et code à 6 chiffres (un assistant **« Utiliser ma clé Base32 »** permet aussi de recalculer le code TOTP en environnement de test).

---

## 4. Visite guidée et test des 8 écrans de la console

| # | Écran | URL | Que vérifier et tester |
|---|---|---|---|
| 1 | **Vue d'ensemble** | `/` | Jauge radiale de score global (0–100), 6 cartes KPI cliquables, courbes Chart.js `24 h` / `7 j` / `30 j`, répartition par niveau/type/canal, flux temps réel SignalR (pastille verte *Temps réel connecté*), bascule thème **Sombre SOC / Clair** en haut à droite. |
| 2 | **Alertes** | `/alerts` | Filtrer par statut, niveau, type de menace, poste ou texte. Cliquer sur une alerte pour ouvrir `/alerts/{id}` et inspecter l'explicabilité IA/Règles, la barre de progression de la chaîne d'attaque, les tags **MITRE ATT&CK** (survoler pour voir la description), la chronologie des événements corrélés et tester **Approuver**, **Faux positif (Rejeter)** *(réinjecté dans la baseline)*, **Acquitter** ou **Résoudre**. |
| 3 | **Graphe de corrélation** | `/graph` | Explorer les nœuds (`Process`, `File`, `Domain`, `IP`, `Device`, `User`, `Host`, `Threat`, `Event`) et leurs clusters corrélés. Changer le layout (`Cose`, `Hiérarchique`, `Concentrique`, `Cercle`, `Grille`), filtrer par score/fenêtre/poste, cliquer sur un nœud ou un cluster pour ouvrir l'inspecteur latéral, exporter en **PNG**. |
| 4 | **Fiches Postes & Entités** | `/entities` | Basculer entre les **Postes surveillés** et l'**Annuaire d'entités**. Ouvrir une fiche (ex. `WS-FINANCE-01`) pour consulter la **baseline comportementale** (grille 24 h des heures habituelles, processus/domaines fréquents, rythme de frappe moyen en touches/s) et vérifier le bandeau rappelant que la consultation est auditée. |
| 5 | **Actions & blocages** | `/actions` | Inspecter les tickets d'actions (simulées, proposées, exécutées, annulées). Créer un blocage via **« ＋ Nouveau blocage manuel »** et tester l'**annulation en un clic (`↩ Annuler`)** (exigence F7 de réversibilité). |
| 6 | **Rapports & Évaluation** | `/reports` | Générer et télécharger un véritable rapport **PDF** (QuestPDF) ou **JSON** sur une période/poste donnée. Consulter la section **Évaluation scientifique — Time-To-Detect (A vs B vs C)** et ses deux graphiques comparatifs. |
| 7 | **Paramètres** | `/settings` | Basculer le mode global (**Apprentissage 7 j**, **Simulation**, **Actif**), ajuster les 4 sliders de seuils (spectre 0–100 temps réel), gérer les collecteurs, les listes d'exclusions, la configuration Ollama, les fenêtres de corrélation et enregistrer via la barre flottante. |
| 8 | **Audit & Intégrité** | `/audit` | Cliquer sur **« Vérifier les chaînes de hash »** pour contrôler cryptographiquement (`SHA-256`) les journaux d'audit et d'événements. Vérifier que vos connexions et consultations de fiches (`EntityProfileViewed`) y figurent. |

---

## 5. Exécution des tests automatisés et du benchmark scientifique

### 5.1 Tests unitaires et d'intégration (70 tests)

```powershell
# Restaurer une fois si nécessaire
dotnet restore Sentinel.slnx

# Compiler toute la solution
dotnet build Sentinel.slnx --no-restore

# Exécuter les 3 suites (Core : 34, Agent : 26, Server : 10)
dotnet test Sentinel.slnx --no-restore
```

### 5.2 Benchmark scientifique A vs B vs C (Time-To-Detect)

Compare automatiquement les 3 configurations sur **8 scénarios d'attaque MITRE ATT&CK** + **219 événements bénins** :
- **(A)** Règles seules
- **(B)** Règles + IA locale
- **(C)** Règles + IA + Corrélation & escalade précoce

```powershell
# Exécuter le benchmark et générer docs/evaluation-results.md + docs/evaluation-results.json
.\scripts\run-simulation.ps1

# Ou avec Ollama réel s'il est démarré localement :
.\scripts\run-simulation.ps1 -Ollama -OllamaModel "qwen2.5:7b"
```

### 5.3 Injecter de nouveaux événements simulés vers un serveur en cours d'exécution

```powershell
dotnet run --project tests/Sentinel.Simulation/Sentinel.Simulation.csproj --no-build -- --push-grpc https://localhost:5181 --delay-ms 150
```

Si `Sentinel.Server` tourne en parallèle avec la console ouverte sur `/`, les nouvelles alertes et mises à jour de score apparaîtront **en direct** via SignalR.

---

## 6. Tester les composants Windows complets (Agent, Tray, Extension, Watchdog, Installeur)

- **Compagnon Barre Système (`Sentinel.Tray`)** : affiche l'icône bouclier (émeraude/ambre/rouge), surveille le presse-papiers (hash + domaine/type uniquement, jamais le texte brut) et le rythme de frappe (horodatages inter-touches uniquement, jamais les touches).
  ```powershell
  dotnet run --project src/Sentinel.Tray/Sentinel.Tray.csproj
  ```
- **Agent de collecte (`Sentinel.Agent`)** : démarre les 6 collecteurs système (`Process`, `Network`, `FileSystem`, `Session`, `Device`, `Installation`), le serveur Named Pipe (`Sentinel.Agent.Ipc`), l'outbox SQLite locale et le client gRPC mTLS. *(Lancer en tant qu'Administrateur pour l'accès complet ETW noyau et journal Sécurité Windows ; sans droits admin, l'agent bascule proprement en mode dégradé WMI/polling).*
  ```powershell
  dotnet run --project src/Sentinel.Agent/Sentinel.Agent.csproj
  ```
- **Extension navigateur Chrome / Edge (`extension/`)** :
  1. Ouvrez `chrome://extensions` (ou `edge://extensions`), activez le **Mode développeur**, puis cliquez sur **Charger l'extension non empaquetée** et sélectionnez le dossier `extension/`.
  2. Pour activer le relais Native Messaging, lancez l'installeur ou enregistrez le manifeste `extension/native-host-manifest.json` pointant vers `Sentinel.BrowserHost.exe`.
- **Installeur complet & Setup autonome (`Sentinel.Installer` + `build-installer.ps1`)** :
  ```powershell
  # Construire le package Setup complet dans dist\ (archive ZIP + dossier exécutable avec payload intégré)
  .\scripts\build-installer.ps1

  # Lancer le Setup graphique (écran de consentement explicite §2.3 -> déploiement -> services Windows)
  .\dist\Sentinel-Setup-v1.0.0\Sentinel.Installer.exe

  # Ou installer via CLI (exemple sans toucher aux services Windows) :
  .\dist\Sentinel-Setup-v1.0.0\Sentinel.Installer.exe --accept-consent --install-certs --install-dir "C:\Temp\Sentinel"
  ```
  Déploie l'ensemble des binaires, enregistre `consent.json`, génère la PKI mTLS, calcule `integrity-manifest.json` (SHA-256), installe optionnellement les services Windows (`SentinelServer`, `SentinelAdmin`, `SentinelAgent`, `SentinelWatchdog`) et enregistre la désinstallation dans Windows (`Sentinel.Installer.exe --uninstall`).
