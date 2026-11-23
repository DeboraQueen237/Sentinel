# Sources de détection et moteurs locaux — SENTINEL v2

> Référence technique des 7 nouvelles sources et moteurs ajoutés dans **SENTINEL v2.0.0** (Missions 1 à 7).

---

## 1. Microsoft Defender & Sysmon optionnel (Mission 1)

### 1.1 Collecteur Microsoft Defender (`DefenderCollector`)

- **WMI (`root\Microsoft\Windows\Defender`)** : interroge `MSFT_MpThreatDetection`, `MSFT_MpThreat`, `MSFT_MpComputerStatus` et `MSFT_MpPreference` pour détecter les menaces identifiées, l'état de la protection temps réel et les nouvelles exclusions.
- **Journal Windows (`Microsoft-Windows-Windows Defender/Operational`)** : écoute les événements :
  - `1116` (menace détectée), `1117` (action appliquée), `1118`/`1119` (échec d'action critique),
  - `5001` (protection temps réel désactivée), `5007` (modification de configuration / ajout d'exclusion), `5010`/`5012` (analyse/virus désactivés), `5101` (protection temps réel expirée).
- **Garantie** : les événements `EventCategory.Defender` ne sont **jamais** exclus par `EventPreFilter`.

### 1.2 Collecteur Sysmon optionnel (`SysmonCollector`)

- **Politique de licence** : Microsoft Sysinternals interdit la redistribution de Sysmon. SENTINEL n'embarque **jamais** Sysmon.
- **Détection automatique** : `SysmonCollector.ProbeInstalled()` vérifie la présence du journal `Microsoft-Windows-Sysmon/Operational` et remonte `SysmonInstalled` dans la page **Santé agents** (`/health`).
- **Événements collectés si présent** : Event ID `1` (création processus), `3` (connexion réseau), `11` (création fichier), `12`/`13`/`14` (registre), `22` (requête DNS).

### 1.3 Dédoublonnage multi-sources (`EventDeduplicator`)

Lorsqu'un même fait (ex. création du même PID ou même fichier) est vu par ETW, WMI et Sysmon dans une fenêtre courte, `EventDeduplicator` fusionne l'événement et renseigne `event.sources` (liste des collecteurs concordants) et `event.dedup.count`.

---

## 2. Moteur Sigma natif en C# (Mission 2 — `Sentinel.Detection.Sigma`)

- **Parser** : `YamlDotNet` prenant en charge `title`, `id`, `status`, `level`, `tags`, `logsource`, `detection` (sélections, filtres, conditions avec `and`/`or`/`not`, parenthèses, `1 of ...`, `all of ...`) et modificateurs `contains`, `startswith`, `endswith`, `re`, `all`, `windash`, `base64`, `base64offset`.
- **Performance** : pré-filtrage Aho-Corasick + évaluation AST — benchmark vérifié **1 000 règles × 10 000 événements en ~4 s**.
- **Gestion** : dossier `%ProgramData%\Sentinel\rules\sigma`, rechargement à chaud (`FileSystemWatcher` avec debounce), activation/désactivation par règle et exclusions depuis `/rules`.
- **Règles livrées** : 14 règles de démonstration originales sous licence **MIT** (`rules/sigma/sentinel_win_*.yml`).
- **Mise à jour SigmaHQ (opt-in)** : script [scripts/update-sigma-rules.ps1](../scripts/update-sigma-rules.ps1) téléchargeant à la demande les règles officielles SigmaHQ (licence **DRL 1.1**, jamais embarquées).

### Table de mapping champs Sigma → `SecurityEvent`

| Champ Sigma | Attribut / propriété `SecurityEvent` |
|---|---|
| `Image` | `process.path` (ou `Subject` pour `Process`) |
| `OriginalFileName` | `process.name` |
| `CommandLine` | `cmdline` |
| `ParentImage` | `parent.path` / `parent.name` |
| `ParentCommandLine` | `parent.cmdline` |
| `User` | `UserId` / `target.user` |
| `TargetFilename` | `file.path` / `file.name` |
| `DestinationIp` | `net.remote.ip` |
| `DestinationPort` | `net.remote.port` |
| `DestinationHostname` / `QueryName` | `domain` |
| `TargetObject` | `reg.target.object` / `reg.key` |
| `Details` | `reg.value` |
| `ScriptBlockText` | `script.excerpt` / `script.indicators` |
| `EventID` | `win.event.id` / `sysmon.event.id` |
| `Hashes` / `sha256` | `sha256` / `sysmon.hashes` |

---

## 3. Moteur YARA & Analyse statique PE (Mission 3 — `Sentinel.Detection.Static`)

- **YARA (`YaraScannerService`)** : utilise `dnYara` (`libyara` natif) avec détection préalable via `NativeLibrary.TryLoad("libyara")` (évitant tout plantage de finaliseur natif). Lorsque `libyara.dll` est absente sur le poste, SENTINEL bascule automatiquement et de manière explicite (`EngineName = "ManagedFallback (libyara indisponible)"`) sur `ManagedYaraFallbackEngine` (supportant les chaînes texte/hex/nocase/wide/ascii et conditions `all of`, `any of`, `N of`, `and`/`or`/`not`, sans modules YARA natifs `pe.*`/`elf.*`).
- **Règles YARA** : dossier `%ProgramData%\Sentinel\rules\yara` (5 fichiers / 9 règles MIT incluses : EICAR, PowerShell suspect, scripts LOLBin, heuristiques ransomware, indicateurs PE) + script [scripts/update-yara-rules.ps1](../scripts/update-yara-rules.ps1).
- **Analyse statique PE (`PeStaticAnalyzer` via `PeNet 6.1.2`)** : présence de signature Authenticode, nombre et entropie des sections (détection sections RWX et > 7,2 bits/octet), détection d'imports suspects (injection, anti-debug, crypto, réseau), packers probables (`UPX`, `VMProtect`, `Themida`, `ASPack`, etc.) et anomalies d'horodatage COFF.
- **Limites de ressources** : déclenchement uniquement sur nouveaux fichiers suspects dans dossiers surveillés / nouveaux processus + scan planifié + scan à la demande (`/rules`), **jamais** de scan permanent du disque complet ; taille max configurable (défaut 16–50 Mo), timeout strict par fichier, parallélisme borné (`SemaphoreSlim`).

---

## 4. Renseignement sur les menaces (Mission 4 — `Sentinel.ThreatIntel`)

- **Résilience HTTP** : clients Polly v8 (retry exponentiel avec jitter, timeout strict, circuit breaker).
- **Stockage & latence** : base locale SQLite indexée (`%ProgramData%\Sentinel\threat-intel\threat-intel.db`) doublée d'un **filtre de Bloom en mémoire** (`< 0,5 ms` sur rejet négatif, `< 2 ms` sur hit indexé, **100 % fonctionnel hors-ligne**).
- **Flux supportés & licences** :
  - **abuse.ch** (*MalwareBazaar*, *URLhaus*, *ThreatFox*, *Feodo Tracker*) — **CC0 1.0** (clé gratuite `Auth-Key` lue via `user-secrets`/DPAPI).
  - **OpenPhish Community** — **non commercial uniquement**, désactivé par défaut (opt-in explicite).
  - **PhishTank** — opt-in avec clé API utilisateur.
  - **VirusTotal v3** — **strictement à la demande** par hash SHA-256 uniquement (jamais d'envoi de fichier), clé utilisateur obligatoire.

---

## 5. Classifieur ML de fichiers PE (Mission 5 — `Sentinel.ML`)

- **51 caractéristiques inspirées d'EMBER** extraites via `PeNet` (en-têtes, sections, imports/exports, histogramme d'octets 16 bins, entropie globale, compteurs statistiques de chaînes sans conservation de texte).
- **Entraînement** : `ML.NET FastTreeBinaryTrainer` (GBDT + calibration de Platt) via `Sentinel.ML.Trainer` (`--ember-jsonl`, `--csv`, `--synthetic`).
- **Garde-fou** : contribution bornée à **≤ 35/100** (jamais seul décisif) + explicabilité locale (`CalculateFeatureContribution`). Détails complets dans [docs/ml-evaluation.md](ml-evaluation.md).

---

## 6. Fichiers canari anti-ransomware (Mission 6 — `Sentinel.Agent`)

- Déploie discrètement des fichiers leurres réalistes (`.docx`, `.xlsx`, `.pdf`, `.txt`) dans les dossiers utilisateur choisis (configurable), enregistrés dans `%ProgramData%\Sentinel\canaries\canaries.json` avec leur empreinte SHA-256.
- Surveille toute modification, renommage, chiffrement (entropie élevée) ou suppression → score critique **94–98** et réponse réversible immédiate.

---

## 7. Visibilité scripts sans fournisseur AMSI managé (Mission 7 — `Sentinel.Agent`)

- **Choix technique délibéré** : Microsoft déconseille l'implémentation d'un fournisseur AMSI COM en code managé .NET (risque de chargement du CLR dans tous les processus système et de deadlock).
- **Alternative sûre implémentée** : lecture du journal `Microsoft-Windows-PowerShell/Operational` (**Event ID 4104** — *Script Block Logging*) + consommation optionnelle en lecture seule du fournisseur ETW `Microsoft-Antimalware-Scan-Interface`.
- **Confidentialité** : analyse en mémoire uniquement ; seuls le hash SHA-256, la longueur, l'entropie, le score d'obfuscation et les indicateurs comportementaux sont conservés par défaut (extrait tronqué ≤ 300 car. avec caviardage des secrets désactivé par défaut).
- Script d'activation guidé avec consentement : [scripts/enable-script-logging.ps1](../scripts/enable-script-logging.ps1).
