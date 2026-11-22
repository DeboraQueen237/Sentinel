# Plan de test et protocole d'évaluation scientifique

> Plan de validation technique et protocole expérimental de **SENTINEL** (cohérent avec les sections §1.2, §8.4 et §14 de `SENTINEL_Documentation.md` et le projet `tests/Sentinel.Simulation`).

---

## 1. Hypothèse scientifique testée

SENTINEL démontre une **prévention mesurable** (et non une prédiction abstraite). L'hypothèse expérimentale évaluée est :

> *La corrélation contextuelle d'événements individuellement faibles réduit le délai de détection d'une chaîne d'attaque (**Time-To-Detect**, en secondes et en nombre d'événements) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*

---

## 2. Environnement et règles de sécurité des tests

> [!WARNING]
> Les tests impliquant des simulations d'attaque sur un système réel (collecteurs actifs + exécuteur d'actions) doivent **impérativement** être exécutés dans une **machine virtuelle isolée** (Hyper-V, VirtualBox ou VMware) dotée d'instantanés (*snapshots*), ou dans **Windows Sandbox**, sans accès à un réseau de production.

- **Aucun logiciel malveillant réel** n'est utilisé : uniquement le fichier standard inoffensif **EICAR**, des scénarios documentés **Atomic Red Team** et des scripts de simulation bénins opérant dans un répertoire temporaire dédié (`%TEMP%\SentinelTest`).
- Les tests automatisés unitaires et d'intégration utilisent la variable `SENTINEL_DATA_DIR` pointant vers un répertoire temporaire isolé afin de ne jamais altérer `%ProgramData%\Sentinel`.

---

## 3. Scénarios de simulation (8 scénarios d'attaque + bruit bénin)

Chaque scénario peut être rejoué de façon déterministe par `tests/Sentinel.Simulation` contre `IThreatPipeline` (en mémoire ou via gRPC contre `Sentinel.Server`) et validé en conditions réelles en VM.

| # | Scénario | Outil / Mécanisme de simulation (inoffensif) | Séquence d'événements simulée (`EventTypes`) | MITRE ATT&CK | Résultat attendu (Config C) |
|---|---|---|---|---|---|
| 1 | **Fichier test EICAR** | Création d'un fichier contenant la chaîne standard EICAR dans `Downloads` / dossier test | `FileCreated` (empreinte EICAR) → éventuel `ProcessStart` | `T1204.002` | Détection immédiate (score ≥ 90, `Malware`), quarantaine réversible en mode `Active` |
| 2 | **Phishing → exécution** | Page HTML locale + URL raccourcie copiée → clic → téléchargement d'un exécutable bénin → exécution → connexion locale simulée | `ClipboardUrl` → `LinkClicked` → `DownloadStarted` → `FileCreated` (`facture.pdf.exe`) → `ProcessStart` → `NetworkConnection` | `T1566`, `T1566.002`, `T1204`, `T1105`, `T1071` | Alerte corrélée dès le **2ᵉ–3ᵉ événement** (avant l'exécution du binaire !), chaîne `chain-phishing-exec` reconnue |
| 3 | **BadUSB** | Microcontrôleur Raspberry Pi Pico / Digispark (ou simulation `Sentinel.Simulation`) émulant un clavier HID injectant une commande bénigne `whoami` via PowerShell | `UsbInserted` (`device.keyboard=true`) → `TypingStats` (`typing.kps > 25`, faible écart-type, `typing.injected=true`) → `ProcessStart` (`powershell.exe`) | `T1200`, `T1056`, `T1059.001` | Escalade rapide au 2ᵉ événement (`UsbInserted` + `TypingStats`), niveau 4 à `ProcessStart`, proposition/désactivation PnP |
| 4 | **Ransomware simulé** | Script créant 50 fichiers factices dans `%TEMP%\SentinelTest`, les chiffrant en AES (entropie ≈ 7,9) et les renommant en `.locked` | `ProcessStart` (non signé) → `FileModified` × N → `FileBurst` (`burst.entropy.avg > 7,5`) → `FileRenamed` (changements d'extension) | `T1486` | Détection critique (`Ransomware`), arrêt du processus factice + protection du dossier réversible |
| 5 | **Exfiltration de données** | Création d'une archive `.zip` volumineuse suivie d'un transfert sortant important vers un domaine rare/serveur local de test | `FileCreated` (`file.archive=true`) → `DnsQuery` (domaine rare) → `NetworkVolume` (volume sortant anormal) | `T1560`, `T1041`, `T1071` | Alerte `Exfiltration`, score cluster > score individuel de chaque étape, blocage des connexions sortantes réversible |
| 6 | **Brute force / intrusion** | Tentatives répétées d'authentification échouées suivies d'une connexion réussie hors horaires habituels et d'un lancement d'outil système | `LogonFailure` (4625) × 5 → `LogonSuccess` (4624, 03h00) → `ProcessStart` (`cmd.exe` / `net.exe`) | `T1110`, `T1078`, `T1059.003` | Alerte `Intrusion` dès la rafale d'échecs, niveau critique après succès + commande inhabituelle |
| 7 | **Persistance** | Installation d'un utilitaire non signé + ajout d'une valeur dans `HKCU\...\Run` + création d'une tâche planifiée factice | `AppInstalled` / `FileCreated` → `StartupEntryAdded` → `ScheduledTaskCreated` | `T1547.001`, `T1053.005` | Chaîne `chain-persistence` détectée, score relevé à niveau 3–4 |
| 8 | **Ingénierie sociale** | Lien raccourci copié → domaine très récent (`domain.age.days = 2`) → téléchargement d'un fichier à double extension (`contrat.docx.exe`) | `ClipboardUrl` (`url.shortener=true`) → `UrlVisited` → `DownloadStarted` / `FileCreated` (`file.double.ext=true`) | `T1566.002`, `T1036.007`, `T1204` | Sensibilisation utilisateur dès le 1er lien + alerte admin avant ouverture du fichier |
| 9 | **Bruit bénin (témoin FPR)** | Activité bureautique normale : navigateur sur domaines habituels (`github.com`, `microsoft.com`), édition de documents, frappes humaines régulières | Flux continu d'événements légitimes (100+ événements) | — | **0 alerte critique**, taux de faux positifs nul ou quasi nul |

---

## 4. Protocole expérimental comparatif (A vs B vs C)

Chaque scénario est exécuté dans trois configurations strictement contrôlées (stockées dans `EvaluationMetrics` et consultables via `GET /api/reports/evaluation`) :

| Configuration | Règles + Baseline | LLM local (Ollama) | Moteur de corrélation | Paramètres `SentinelSettings` |
|---|---|---|---|---|
| **Config A** *(Référence règles)* | Activé | Désactivé | Désactivé | `Llm.Enabled = false`, `Correlation.Enabled = false` |
| **Config B** *(IA sans corrélation)* | Activé | Activé | Désactivé | `Llm.Enabled = true`, `Correlation.Enabled = false` |
| **Config C** *(SENTINEL complet)* | Activé | Activé | **Activé** | `Llm.Enabled = true`, `Correlation.Enabled = true`, `EarlyEscalation = true` |

### Protocole d'exécution

1. Réinitialiser la baseline avec un jeu d'entraînement bénin identique (heures 08h–18h, domaines et processus courants) pour A, B et C.
2. Rejouer les 8 scénarios d'attaque + le flux témoin bénin avec des horodatages reproductibles dans chaque configuration.
3. Enregistrer pour chaque `(Scenario, Configuration)` :
   - si une alerte administrateur (`Score >= 75` ou escalade) est levée (`Detected`),
   - le rang de l'événement déclencheur (`EventsBeforeAlert`),
   - le temps écoulé depuis le premier événement du scénario (`SecondsToDetect`),
   - le score maximal atteint (`PeakScore`),
   - le nombre d'alertes sur le flux bénin (`FalsePositives`).
4. Calculer le **gain de prévention** de (C) sur (A) et (B) :
   - $\Delta \text{TTD}_{\text{événements}} = \text{EventsBeforeAlert}_{A/B} - \text{EventsBeforeAlert}_{C}$
   - $\Delta \text{TTD}_{\text{secondes}} = \text{SecondsToDetect}_{A/B} - \text{SecondsToDetect}_{C}$

---

## 5. Métriques d'évaluation et critères d'acceptation

| Catégorie | Métrique | Formule / Mesure | Cible d'acceptation |
|---|---|---|---|
| **Efficacité détection** | Taux de détection (Rappel) | $\frac{\text{VP}}{\text{VP} + \text{FN}}$ sur les 8 scénarios | **≥ 90 %** (8/8 scénarios en Config C) |
| **Précision** | Précision | $\frac{\text{VP}}{\text{VP} + \text{FP}}$ | **≥ 90 %** |
| **Faux positifs** | FPR / jour | Alertes injustifiées sur flux bénin | **≤ 1 / jour** (0 sur le jeu témoin) |
| **Prévention (clé)** | Time-To-Detect (TTD) | Événements et secondes avant 1ʳᵉ alerte | Config C strictement meilleure que A et B (alerte dès le **2ᵉ–3ᵉ événement** sur chaînes progressives) |
| **Latence** | Latence pipeline (hors LLM) | Moyenne `PipelineStats.AvgPipelineLatencyMs` | **< 10 ms / événement** |
| **Latence IA** | Latence scoring LLM (Ollama) | Moyenne `PipelineStats.AvgLlmLatencyMs` (ratio d'appel ~5–10 %) | **< 3 s** (timeout strict à 10 s) |
| **Empreinte agent** | CPU moyen / RAM moyenne | `HeartbeatRequest` sur 1 h d'usage bureautique | **< 3 % CPU**, **< 150 Mo RAM** |
| **Réversibilité (F7)** | Taux de succès d'annulation | Annulation de quarantaine, pare-feu, hosts, PnP | **100 %** de restauration à l'état initial |
| **Intégrité** | Détection d'altération DB | Modification/suppression d'une ligne SQLite → `IntegrityVerifier` | **100 %** des altérations détectées avec `FirstBrokenId` exact |

---

## 6. Suite de tests automatisés

La solution `Sentinel.slnx` inclut quatre projets de tests et validation :

| Projet | Portée des tests |
|---|---|
| `tests/Sentinel.Core.Tests` | Règles déterministes, baseline comportementale, garde-fous anti prompt-injection (`Sentinel.AI`), formule de score de cluster, escalade précoce au 2ᵉ événement, détection des 7 chaînes d'attaque, matrice de décision et modes `Learning`/`Simulation`/`Active`. |
| `tests/Sentinel.Agent.Tests` | Normalisation des événements, calcul d'entropie/double extension, outbox SQLite locale, statistiques inter-touches (vérification qu'aucun code touche n'est stocké), réversibilité des actions. |
| `tests/Sentinel.Server.Tests` | Authentification PBKDF2 + TOTP, `HashChainWriter` sous forte concurrence, `IntegrityVerifier` (détection de falsification), `RetentionCleaner`, API REST, gRPC `AgentGateway` et export de rapports. |
| `tests/Sentinel.Simulation` | Exécutable CLI rejouant les scénarios d'attaque dans les configurations **A**, **B** et **C**, affichant le tableau comparatif TTD et exportant les résultats (`ScenarioMetricDto`). |

### Commandes d'exécution

```powershell
# Lancer tous les tests unitaires et d'intégration
dotnet test Sentinel.slnx --configuration Release

# Lancer la simulation comparative A vs B vs C
dotnet run --project tests/Sentinel.Simulation/Sentinel.Simulation.csproj
```
