# SENTINEL v2 — Rapport d'évaluation scientifique et reproductible (Mission 10)

> **Date de mesure** : 22–23 novembre 2026  
> **Plateforme de test** : Windows 11 x64 — .NET 10.0.9 (`Sentinel.slnx`, 21 projets) — Ollama local `qwen2.5-coder:3b` (`f72c60cabf62`, 1,9 Go, exécution CPU)  
> **Artefacts bruts générés automatiquement** : [evaluation-results.md](evaluation-results.md), [evaluation-results-ollama.md](evaluation-results-ollama.md), [evaluation-results.json](evaluation-results.json), [ml-evaluation.md](ml-evaluation.md).

---

## 1. Hypothèse scientifique et protocole reproductible

### 1.1 Hypothèse évaluée

> *La corrélation contextuelle (graphe temporel + chaîne de Markov + escalade précoce au 2ᵉ événement) d'événements individuellement faibles réduit significativement le délai de détection d'une chaîne d'attaque (**Time-To-Detect**, en secondes et en nombre d'événements) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*

### 1.2 Commande de reproduction

```powershell
# 1) Exécution déterministe (reproductible en CI, 0 dépendance réseau)
dotnet run --project tests/Sentinel.Simulation -- --output-md docs/evaluation-results.md --output-json docs/evaluation-results.json

# 2) Exécution réelle contre Ollama local (qwen2.5-coder:3b)
dotnet run --project tests/Sentinel.Simulation -- --ollama --ollama-url http://localhost:11434 --ollama-model qwen2.5-coder:3b --output-md docs/evaluation-results-ollama.md
```

### 1.3 Jeu d'évaluation v2

- **Corpus bénin de fond sur 24 heures simulées (`00h00–23h59`, 459 événements)** :
  - Activité bureautique de journée (`08h30–17h30`) : processus signés Microsoft/Google/Mozilla (`WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`, `chrome.exe`, `msedge.exe`, `firefox.exe`, `Teams.exe`, `Code.exe`), navigation/HTTPS vers domaines habituels, fichiers bureautiques basse entropie (3,8–5,4 bits/octet), cadence de saisie humaine (~5 touches/s, σ ≈ 45 ms), cycle de session et erreur isolée de mot de passe.
  - Activité de fond sur 24 h (nuit et soirée) : processus système signés (`MsMpEng.exe`, `SearchIndexer.exe`, `OneDrive.exe`, `UsoClient.exe`, `svchost.exe`, `dotnet.exe`), résolutions/flux HTTPS vers `windowsupdate.com`/`microsoft.com`/`github.com`/`office.com`, blocs PowerShell 4104 d'administration bénins sans obfuscation et écritures journaux basse entropie.
- **11 scénarios d'attaque bénins/simulés (8 scénarios v1 + 3 scénarios v2)** :
  - **S1** Phishing → exécution (`T1566.002`, `T1204`, `T1071`)
  - **S2** BadUSB HID → PowerShell (`T1200`, `T1056`, `T1059.001`)
  - **S3** Ransomware simulé (`T1486`)
  - **S4** Exfiltration de données (`T1560`, `T1041`, `T1052`)
  - **S5** Brute force → intrusion (`T1110`, `T1078`, `T1059`)
  - **S6** Persistance (`T1204`, `T1547.001`, `T1053.005`)
  - **S7** Ingénierie sociale (`T1566`, `T1566.002`, `T1204.002`)
  - **S8** Fichier EICAR — contrôle positif IOC (`T1204.002`)
  - **S9 (v2)** Affaiblissement Microsoft Defender + LOLBin `certutil` (`T1562.001`, `T1218`, `T1105`)
  - **S10 (v2)** Piège Canari anti-ransomware (`T1486`)
  - **S11 (v2)** Visibilité script PowerShell 4104 obfusqué → bypass journalisation → C2 (`T1059.001`, `T1027`, `T1562.006`, `T1071`)
- **3 configurations comparées à iso-moteur Sigma** (les 14 règles Sigma natives de `rules/sigma/` sont actives dans A, B et C afin d'isoler strictement l'effet causal de l'IA et de la corrélation) :
  - **Config A** : Règles déterministes + Sigma + Baseline (sans IA, sans corrélation).
  - **Config B** : Règles + Sigma + Baseline + IA locale (sans corrélation).
  - **Config C** : SENTINEL v2 Complet (Règles + Sigma + Baseline + IA + Corrélation Markov + escalade précoce au 2ᵉ événement).

Un scénario est considéré détecté dès qu'une décision atteint le niveau **Élevé (≥ 75)** ou déclenche `AlertAdmin = true`.

---

## 2. Résultats A vs B vs C — Exécution 1 : Analyste IA déterministe (CI)

| Configuration | Détections | Rappel | Précision | Faux positifs (459 évts / 24 h) | Évts moy. avant alerte | TTD moyen | Latence moy. | RAM | Appels IA |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **A — Règles + Sigma seules** | 11 / 11 | 100,0 % | 100,0 % | 0 (**0,00 %**) | 2,64 | **13,55 s** | 0,124 ms | 45,8 Mo | 0 (0,0 %) |
| **B — Règles + Sigma + IA (simulé)** | 11 / 11 | 100,0 % | 100,0 % | 0 (**0,00 %**) | 2,27 | **10,45 s** | 0,033 ms | 44,9 Mo | 23 (4,6 %) |
| **C — SENTINEL v2 Complet** | 11 / 11 | 100,0 % | 100,0 % | 0 (**0,00 %**) | **1,73** | **6,09 s** | **0,051 ms** | 47,9 Mo | 23 (4,6 %) |

### Gains mesurés (Exécution déterministe)

- **Gain Time-To-Detect (C vs A, apparié)** : `13,55 s → 6,09 s`, soit **-55,0 %** (`-0,91` événement en moyenne).
- **Gain Time-To-Detect (C vs B, apparié)** : `10,45 s → 6,09 s`, soit **-41,7 %** (`-0,55` événement en moyenne).
- **Règle d'escalade précoce au 2ᵉ événement** : **100 % validée** sur les chaînes multi-étapes (moyenne `1,80` événement avant alerte en Config C).
- **Taux de faux positifs sur 24 h simulées (459 événements)** : **0 FP (0,00 %)** dans A, B et C.

### Détail par scénario (Exécution déterministe)

| Scénario | MITRE ATT&CK | (A) Règles+Sigma | (B) + IA simulée | (C) + Corrélation Markov | Gain TTD (C vs A) |
|---|---|---|---|---|---:|
| S1 — Phishing → exécution | `T1566.002`, `T1204`, `T1071` | Evt #3 (18,0 s) | Evt #3 (18,0 s) | **Evt #2 (6,0 s)** | **-66,7 %** |
| S2 — BadUSB | `T1200`, `T1056`, `T1059.001` | Evt #3 (5,0 s) | Evt #3 (5,0 s) | **Evt #2 (2,0 s)** | **-60,0 %** |
| S3 — Ransomware simulé | `T1486` | Evt #1 (0,0 s) | Evt #1 (0,0 s) | Evt #1 (0,0 s) | 0 % *(Sigma Temp)* |
| S4 — Exfiltration | `T1560`, `T1041`, `T1052` | Evt #4 (40,0 s) | Evt #3 (26,0 s) | **Evt #2 (12,0 s)** | **-70,0 %** |
| S5 — Brute force → intrusion | `T1110`, `T1078`, `T1059` | Evt #5 (32,0 s) | Evt #3 (16,0 s) | **Evt #2 (8,0 s)** | **-75,0 %** |
| S6 — Persistance | `T1204`, `T1547.001`, `T1053.005` | Evt #2 (15,0 s) | Evt #2 (15,0 s) | Evt #2 (15,0 s) | 0 % |
| S7 — Ingénierie sociale | `T1566`, `T1566.002`, `T1204.002` | Evt #4 (9,0 s) | Evt #3 (5,0 s) | **Evt #2 (3,0 s)** | **-66,7 %** |
| S8 — Fichier EICAR (IOC) | `T1204.002` | Evt #1 (0,0 s) | Evt #1 (0,0 s) | Evt #1 (0,0 s) | 0 % *(IOC connu)* |
| S9 (v2) — Affaiblissement Defender | `T1562.001`, `T1218`, `T1105` | Evt #2 (12,0 s) | Evt #2 (12,0 s) | Evt #2 (12,0 s) | 0 % *(Règle DEF)* |
| S10 (v2) — Piège Canari | `T1486` | Evt #1 (0,0 s) | Evt #1 (0,0 s) | Evt #1 (0,0 s) | 0 % *(Sigma Temp)* |
| S11 (v2) — PowerShell 4104 | `T1059.001`, `T1027`, `T1562.006`, `T1071` | Evt #3 (18,0 s) | Evt #3 (18,0 s) | **Evt #2 (9,0 s)** | **-50,0 %** |

---

## 3. Résultats A vs B vs C — Exécution 2 : Ollama local réel (`qwen2.5-coder:3b`)

Une seconde exécution complète a été réalisée en direct contre l'instance Ollama locale de la machine de test (`http://localhost:11434`, modèle `qwen2.5-coder:3b`, exécution CPU, timeout porté à 30 s par appel).

| Configuration | Détections | Rappel | Précision | Faux positifs (459 évts) | Évts moy. | TTD moyen | Latence moy. (tous évts) | RAM | Réponses LLM acceptées |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **A — Règles + Sigma seules** | 11 / 11 | 100,0 % | 100,0 % | 0 (0,00 %) | 2,64 | **13,55 s** | 0,265 ms | 53,5 Mo | 0 |
| **B — Règles + Sigma + `qwen2.5-coder:3b`** | 11 / 11 | 100,0 % | 100,0 % | 0 (0,00 %) | 2,64 | **13,55 s** | **595,84 ms** | 52,0 Mo | **0** *(timeouts CPU 30 s)* |
| **C — SENTINEL v2 + `qwen2.5-coder:3b`** | 11 / 11 | 100,0 % | 100,0 % | 0 (0,00 %) | **1,73** | **6,09 s** | **710,61 ms** | 53,8 Mo | **2** *(0,4 %, reste en repli)* |

### Analyse honnête de l'exécution Ollama CPU réelle

1. **Temps d'inférence CPU de `qwen2.5-coder:3b`** : sur cette machine sans GPU dédié (et sous charge de développement concurrente), la génération JSON structurée sur un prompt de contexte SOC par `qwen2.5-coder:3b` a dépassé le timeout de **30 s** sur la majorité des événements de la bande ambiguë (`25–80`), d'où une latence moyenne par scénario comprise entre `3,75 s` et `14,73 s` par événement et seulement `2` réponses JSON validées dans le délai en Config C.
2. **Résilience prouvée du repli déterministe** : dans 100 % des cas de timeout ou de sortie non conforme au schéma, `OllamaAssessor` a basculé automatiquement sur le scoring déterministe (règles + Sigma + corrélation) **sans aucun blocage, sans exception non gérée et avec 0 % de faux positifs**.
3. **Origine réelle du gain de détection** : cette mesure comparative prouve un résultat scientifique essentiel — sur matériel grand public sans GPU, **la réduction de `-55,0 %` du Time-To-Detect (`13,55 s → 6,09 s`) est assurée de façon fiable et déterministe par le moteur de corrélation Markovien et les règles Sigma**, et non par un modèle 3B lent en CPU. Pour obtenir un enrichissement LLM temps réel `< 3 s`, il est recommandé soit d'utiliser une accélération GPU locale, soit de précharger (`keep_alive`) un modèle plus léger (ex. `qwen2.5:1.5b` ou `phi3:mini` quantifié Q4).

---

## 4. Benchmarks des nouveaux moteurs v2 et test automatisé de confidentialité

| Moteur / Vérification | Test automatisé exécuté | Mesure observée | Cible | Statut |
|---|---|---|---|---|
| **Moteur Sigma natif C# (M2)** | `SigmaEngineTests.Benchmark_1000Rules_10000Events_CompletesUnder5Seconds` | **~4 s** pour 1 000 règles × 10 000 événements (même sous charge CPU Ollama) | < 5 s | **Réussi** |
| **Threat Intel Bloom + SQLite (M4)** | `ThreatIntelTests.LookupBenchmark_NegativeBloomAndIndexedSqliteHit_ShouldBeUnder5Ms` | Rejet négatif Bloom `< 0,5 ms` (typ. `< 0,05 ms`), hit SQLite indexé (10 000 IOC) `< 2 ms` moy., 100 % hors-ligne | < quelques ms | **Réussi** |
| **Classifieur ML PE (M5)** | `Sentinel.ML.Trainer --synthetic --samples 10000` | `ROC-AUC = 0,9995`, `Recall @ 0,1 % FPR = 96,10 %` *(jeu synthétique uniquement — voir [ml-evaluation.md](ml-evaluation.md))* | Validation technique | **Réussi** *(synthétique)* |
| **Analyse statique PE + YARA (M3)** | `StaticAnalysisTests` (15 tests) | `PeNet` réel + `ManagedYaraFallbackEngine` (`libyara.dll` absente), timeout/taille/parallélisme bornés | Borné & sûr | **Réussi** *(repli géré)* |
| **Invariant de vie privée en base (M10)** | `V2HardeningAndDetectionEndpointsTests.PrivacyInvariant_SqlLiteDatabaseMustContainZeroRawUserContent` | Inspection directe de `sentinel.db` après ingestion d'événements contenant secrets/textes factices : **0 octet de contenu utilisateur stocké** | 0 fuite | **Réussi** |
| **Suite complète de tests automatisés** | `dotnet test Sentinel.slnx --no-build` | **179 / 179 tests verts** (`Agent`: 37, `Core`: 37, `Detection`: 91, `Server`: 14) | 100 % vert | **Réussi** |

---

## 5. Protocole Atomic Red Team (VM isolée uniquement)

Le script [scripts/run-atomic-red-team-vm.ps1](../scripts/run-atomic-red-team-vm.ps1) orchestre un jeu de techniques défensives/inoffensives mappées à MITRE ATT&CK (`T1059.001`, `T1218`, `T1053.005`, `T1547.001`, `T1562.001`, `T1082`, fichier EICAR) avec garde-fou obligatoire (`-ConfirmIsolatedVm`), mode `-DryRun`, et vérification d'environnement VM.

> **Transparence** : conformément aux règles non négociables, **aucun test Atomic Red Team n'a été exécuté sur la machine de développement**. Le script est vérifié en syntaxe / `-DryRun` et destiné exclusivement à une VM Windows 11 isolée avec snapshot préalable.

---

## 6. Échecs constatés, limites et menaces à la validité

1. **Biais de construction du corpus simulé (validité interne)** : les 11 scénarios et le corpus bénin 24 h ont été conçus par l'équipe qui a écrit les règles. Un taux de rappel de `100 %` et un FPR de `0,00 %` sur ce banc ne garantissent pas les mêmes chiffres en environnement d'entreprise hétérogène (outils d'administration internes, scripts métiers non signés, installateurs compressés).
2. **Effet de plafond Sigma sur S3 et S10** : l'activation de la règle Sigma `sentinel_win_temp_execution` a déclenché une alerte dès l'événement #1 (lancement d'un binaire non signé depuis `%TEMP%`) sur S3 et S10 dans toutes les configurations (A, B, C), ce qui neutralise la mesure du gain différentiel de la corrélation sur ces deux scénarios — et souligne un risque de faux positifs en production si des installateurs légitimes s'exécutent depuis `%TEMP%` sans exclusion ou période d'apprentissage.
3. **Latence CPU d'Ollama (`qwen2.5-coder:3b`)** : mesurée de manière transparente en §3 — sur CPU seul, les timeouts de 30 s empêchent d'exploiter pleinement l'enrichissement LLM en temps réel, même si le repli déterministe préserve la détection.
4. **Absence de `libyara.dll` native** : le paquet `dnYara` ne distribue pas la DLL native `libyara.dll`. L'évaluation YARA repose donc sur `ManagedYaraFallbackEngine` (sous-ensemble documenté des règles YARA sans modules PE/ELF YARA natifs).
5. **Jeu synthétique ML** : le modèle `2.0.0-synthetic` valide le pipeline d'extraction/entraînement/calibration/explicabilité mais ne doit pas être confondu avec une évaluation sur malwares réels (EMBER 2018 / SOREL-20M requis).
6. **Tests non exécutés sur VM vierge** : l'exécution réelle des tests Atomic Red Team et la validation complète d'installation/mise à niveau/désinstallation silencieuse MSI (`msiexec /qn`) sur une VM Windows 11 vierge restent à exécuter par l'opérateur dans un environnement VM isolé.
