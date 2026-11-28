# Journal des modifications (CHANGELOG)

Toutes les évolutions notables de **SENTINEL** sont consignées ici selon le format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage sémantique (`SemVer`).

---

## [2.2.0] — 2026-11-27 (`main` / `develop`)

### Ajouté
- **Refonte complète du Graphe en Arbre Causal & Flux Temps Réel** (`GraphBuilderService`, `sentinel-graph.js`, `Graph.razor`) :
  - Topologie hiérarchique claire de gauche à droite (`Racine Poste` → `Acteur Utilisateur/USB` → `Processus Parent/Enfant` → `Événement dédupliqué ×N` → `Cible Fichier/Domaine/IP` → `Menace/Alerte`), éliminant l'effet « nid d'abeilles rouge ».
  - Distinction visuelle nette entre **flux causaux directs (`──▶`)** et **corrélations indirectes (`- -▶`)**, traçage complet de branche au clic, recherche instantanée, masquage du bruit système et vue **Flux chronologique temps réel**.
- **Scan Système Général, Audit de Posture en 11 points & Banc de Démo Soutenance** (`SystemScanAndAuditService`, `/scan-audit`) :
  - Scan proactif à la demande et planifié (toutes les 6 h) des processus actifs, connexions TCP, clés `Run`/`RunOnce`, binaires récents (YARA + PeNet + ML PE) et canaris.
  - Audit de sécurité et conformité (`PostureScore /100` : Defender, Pare-feu, UAC, PowerShell 4104, Sysmon, chaîne cryptographique SHA-256, PKI mTLS, Sigma/YARA, ML, Qwen IA).
  - Simulateur temps réel de soutenance (`phishing-chain`, `ransomware-canary`, `badusb-intrusion`, `clear-noise`) + guide [docs/presentation-et-demo.md](docs/presentation-et-demo.md).
- **Notifications temps réel In-App (Cloche + Son) & Canal SMS** (`AlertNotificationService`, `MainLayout.razor`, `Settings.razor`) :
  - Centre de notifications temps réel dans la barre supérieure (actif par défaut via SignalR) et support **SMS** (`TwilioSms` + `HttpGateway` compatible passerelles opérateurs locales/régionales, secrets chiffrés DPAPI).
- **Intervention IA Qwen à 3 niveaux & Sélection CPU/GPU intelligente** (`OllamaModelSelector`, `OllamaAssessor`, `AlertDetail.razor`) :
  - Détection GPU dédié vs CPU seul : privilégie automatiquement `qwen2.5-coder:3b` sur CPU pour une réponse rapide, migration automatique des anciennes bases `v1.0.0`, et bouton **« ✨ Diagnostic & Plan d'Action IA (Qwen) »** sur chaque alerte et cluster.

### Corrigé
- **Auto-réparation de `SqliteEventOutbox` & Anti-tempête `WatchdogWorker`** : corrige l'erreur `SQLite Error 10: disk I/O error` qui provoquait l'arrêt répété de `SentinelAgent` et la génération en boucle d'alertes `AgentTampering` toutes les 10 s (cooldown 15 min + backoff exponentiel + déduplication serveur et bouton de nettoyage en 1 clic).

### Ajouté
- **Notifications administrateur automatiques multi-canaux par niveau de criticité** (`Sentinel.Server`, `Sentinel.Shared`, `Sentinel.Admin`) :
  - Routage indépendant par seuil minimal (`Faible`, `Modéré`, `Élevé`, `Critique`) sur **Email (SMTP TLS/STARTTLS)**, **WhatsApp (Meta Cloud API v21.0 & Twilio)** et **Webhook / Slack / Microsoft Teams / Discord / Telegram** (avec signature `X-Sentinel-Signature` HMAC-SHA256 optionnelle).
  - Déclenchement automatique sur création/escalade d'alerte ET sur **clusters corrélés** (`NotifyOnCorrelatedCluster`).
  - File asynchrone non bloquante (`Channel<T>`), anti-spam par cooldown contourné immédiatement en cas d'escalade de criticité (`Élevé → Critique`), retries avec backoff, historique des 50 derniers envois et journalisation chaînée SHA-256.
  - Confidentialité & sécurité strictes : opt-in (`Enabled = false` par défaut), métadonnées d'alerte assainies uniquement, secrets chiffrés au repos via **Windows DPAPI** (`NotificationSecretStore` + repli `dotnet user-secrets`), jamais persistés en clair dans SQLite ni dans les logs.
  - Endpoints REST `/api/notifications/status`, `/api/notifications/test`, `/api/notifications/secrets` et section complète dans la console Blazor (`/settings`).
- **Sélection automatique intelligente du meilleur modèle Qwen local & optimisation Ollama** (`Sentinel.AI`, `Sentinel.Core`, `Sentinel.Installer`) :
  - `OllamaModelSelector` inspecte `GET /api/tags` (génération `qwen3` > `qwen2.5` > `qwen2` > `qwen`, taille paramétrique, quantification, taille sur disque) et la RAM hôte pour sélectionner automatiquement le meilleur modèle Qwen déjà installé localement sans jamais télécharger de modèle en silence ni saturer la RAM.
  - Optimisation de l'inférence locale : prompt SOC compact anti prompt-injection, `keep_alive` configurable (`10m`), bornage `num_ctx` (`2048`) et `num_predict` (`160`), préchauffage au démarrage (`WarmUpAsync`) et cache sémantique TTL absorbant les rafales similaires en `< 0,1 ms`.
  - Endpoints `/api/system/llm` et `/api/system/llm/autoselect`, indicateurs temps réel dans `/settings` et diagnostic intelligent dans `Sentinel.Installer` v2.1.0.

---

## [2.0.0] — 2026-11-23 (`develop`)

### Ajouté
- **Mission 1 — Microsoft Defender, Sysmon optionnel & dédoublonnage** (`Sentinel.Agent`, `Sentinel.Core`) : collecte WMI (`MSFT_Mp*`) et `Windows Defender/Operational` (détections + affaiblissement : exclusions, arrêt temps réel/service), détection automatique de Sysmon sans jamais l'embarquer, dédoublonnage multi-sources (`EventDeduplicator`).
- **Mission 2 — Moteur Sigma natif C#** (`Sentinel.Detection.Sigma`) : parseur YAML (`YamlDotNet`), conditions complètes (`and/or/not`, `1 of`, `all of`), modificateurs (`contains`, `startswith`, `endswith`, `re`, `all`, `windash`, `base64`), pré-filtrage Aho-Corasick, rechargement à chaud, 14 règles MIT incluses (`rules/sigma/`), script `scripts/update-sigma-rules.ps1` (SigmaHQ DRL 1.1), 55 cas de test et benchmark 1 000 règles × 10 000 événements (~4 s).
- **Mission 3 — Moteur YARA & Analyse statique PE** (`Sentinel.Detection.Static`, `Sentinel.Agent`) : `dnYara` sécurisé par `NativeLibrary.TryLoad` + `ManagedYaraFallbackEngine` documenté, analyseur PE `PeNet` (Authenticode, sections/entropie, imports suspects, packers, horodatage), 9 règles YARA MIT (`rules/yara/`), scan événementiel/planifié/à la demande avec limites strictes de ressources.
- **Mission 4 — Threat Intelligence locale hors-ligne** (`Sentinel.ThreatIntel`) : clients HTTP Polly v8 pour abuse.ch (MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker en CC0), OpenPhish/PhishTank opt-in, VirusTotal on-demand par hash ; SQLite indexé + filtre de Bloom (`< 2 ms` hors-ligne).
- **Mission 5 — Classifieur ML de fichiers PE** (`Sentinel.ML`, `Sentinel.ML.Trainer`) : 51 caractéristiques EMBER-like (`PeNet`), entraîneur `FastTreeBinaryTrainer` (ROC-AUC, Recall @ 0,1 % FPR), score borné (≤ 35/100, jamais seul décisif), explicabilité `CalculateFeatureContribution`, rapport `docs/ml-evaluation.md`.
- **Mission 6 — Fichiers canari anti-ransomware** (`Sentinel.Agent`) : déploiement discret de fichiers leurres avec SHA-256 (`CanaryManager`/`CanaryCollector`), détection modification/renommage/chiffrement/suppression → réponse critique réversible.
- **Mission 7 — Visibilité scripts non invasive** (`Sentinel.Agent`) : PowerShell Script Block Logging Event ID `4104` + ETW AMSI optionnel (sans fournisseur AMSI COM managé), métadonnées/hash par défaut, caviardage automatique des secrets sur extrait opt-in, script `scripts/enable-script-logging.ps1`.
- **Mission 8 — Corrélation avancée & fusion multi-moteurs** (`Sentinel.Core`) : modèle de transitions de Markov (`AttackChainMarkovModel`), feedback VP/FP historisé et réversible, arêtes horodatées, tactiques MITRE, récit chronologique (`ClusterNarrativeBuilder`), ventilation `ScoreContributions`, escalade au 2ᵉ événement préservée.
- **Mission 9 — Auto-protection & durcissement** : verrouillage brute-force admin (5 échecs → 15 min, HTTP `429`), durcissement ACL NTFS (`DirectorySecurityHardener`, `SYSTEM` + `Administrateurs` en mode élevé/service), `.AsSplitQuery()` EF Core, Watchdog avec détection de suppression de service, `EnableNETAnalyzers`, 0 vulnérabilité NuGet connue (`System.Security.Cryptography.Pkcs` épinglé `10.0.15`), test automatisé de confidentialité de `sentinel.db`.
- **Mission 10 — Évaluation reproductible & rapport honnête** (`Sentinel.Simulation`, `docs/evaluation-report.md`) : 11 scénarios (v1+v2), corpus bénin 24 h (459 événements), mesures A/B/C déterministes et en direct contre Ollama local `qwen2.5-coder:3b` (`-55,0 %` TTD, `0,00 %` FPR), script VM-only `scripts/run-atomic-red-team-vm.ps1`.
- **Mission 11 — Console Blazor v2 bilingue FR/EN** (`Sentinel.Admin`) : 5 nouveaux écrans (`/intel`, `/rules`, `/ml`, `/canaries`, `/health`), graphe enrichi (filtre tactique MITRE, récit, ventilation moteurs, Annuler 1 clic), interrupteurs v2, sélecteur FR/EN, vérifié en direct dans Chrome (0 erreur console/réseau).
- **Mission 12 — Documentation complète synchronisée** : mise à jour de `README.md` et tous les guides `docs/` (`architecture`, `detection-sources`, `correlation-rules`, `decision-matrix`, `privacy-and-consent`, `threat-model`, `test-plan`, `admin-guide`, `user-guide`, `install-guide`, `limitations`), `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, documentation XML générée sur les bibliothèques.
- **Mission 13 — Installateur Windows x64 MSI WiX v5 & scripts de build** : projet `Sentinel.Installer.Msi` (WiX v5), mise à niveau `Sentinel.Installer` v2 (détection Defender/Sysmon/Ollama+RAM, ACL NTFS, pare-feu, règles, désinstallation `--delete-data`), `build/build.ps1`, `build/sign.ps1` et CI release sur tags `v*`.

### Modifié
- Modèle Ollama local par défaut adapté à `qwen2.5-coder:3b` (modèle installé localement).

---

## [1.0.0] — 2026-11-22 (`main`)

### Ajouté
- Socle complet SENTINEL v1 (agent Windows Service, `Sentinel.Core`, `Sentinel.AI`, `Sentinel.Storage`, `Sentinel.Server`, `Sentinel.Admin`, `Sentinel.Tray`, `Sentinel.BrowserHost`, `extension/`, `Sentinel.Watchdog`, `Sentinel.Installer`, 70 tests et banc A/B/C).
