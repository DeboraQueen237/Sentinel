# Moteur de corrélation et chaînes d'attaque

> Spécification algorithmique du moteur de corrélation de **SENTINEL** (cohérente avec la section §8 de `SENTINEL_Documentation.md`, `CorrelationSettings`, `CorrelationCluster` et `MitreCatalog`).

---

## 1. Principe et rôle dans le pipeline

Les attaques modernes (phishing, BadUSB, exfiltration lente, ingénierie sociale) se composent souvent d'une succession d'actions individuellement bénignes ou faiblement suspectes (**signaux faibles**). Une analyse événement par événement laisse passer chaque étape jusqu'à la compromission finale.

Le moteur de corrélation de `Sentinel.Core` agit immédiatement après le scoring hybride (règles + baseline + LLM) :
1. Il ne retient pour la corrélation que les événements atteignant au moins `CorrelationSettings.MinEventScore` (par défaut **30**, correspondant au niveau 1 « Faible » — marquage pour corrélation).
2. Il indexe chaque événement en mémoire selon ses **clés de contexte**.
3. Il relie l'événement à ses voisins présents dans les **fenêtres glissantes** configurées et maintient les **clusters** (composantes connexes du graphe de corrélation).
4. Il recalcule le **score agrégé du cluster** (qui peut dépasser le score individuel de chaque événement — exigence **F5**) et applique la règle d'**escalade précoce**.
5. Au redémarrage du serveur, `IThreatPipeline.WarmUpAsync` réhydrate l'index en mémoire à partir des événements récents stockés dans `Sentinel.Storage`.

---

## 2. Clés de contexte

Deux événements $e_i$ et $e_j$ sont candidats à une corrélation s'ils partagent au moins une **clé de contexte** normalisée sur le même poste (`HostId`) ou dans le même périmètre :

| Famille de clé | Format normalisé | Exemples | Type d'arête (`GraphEdgeType`) | Poids de lien par défaut |
|---|---|---|---|---|
| **Entité forte — Domaine** | `domain:<domaine>` | `domain:bit.ly`, `domain:facture-paiement.xyz` | `SameDomain` / `OpenedUrl` | **0,8** (`SameEntityWeight`) |
| **Entité forte — Empreinte** | `hash:<sha256>` | `hash:e3b0c442…` | `SameHash` | **0,8** |
| **Entité forte — Processus / Parent** | `pid:<host>:<pid>`, `parent:<host>:<ppid>` | `parent:PC-01:4812` | `Spawned` / `SameEntity` | **0,8** |
| **Entité forte — Fichier** | `file:<chemin_normalisé>` | `file:downloads/facture.pdf.exe` | `Wrote` / `SameEntity` | **0,8** |
| **Entité forte — IP / Périphérique** | `ip:<ip_distante>`, `device:<vid:pid>` | `ip:185.220.101.4`, `device:2341:8036` | `ConnectedTo` / `SameEntity` | **0,8** |
| **Presse-papiers** | `clip:<content_hash>` | `clip:9f86d081…` | `CopiedFromClipboard` | **0,8** |
| **Type d'anomalie** | `threat:<host>:<ThreatType>` | `threat:PC-01:Phishing` | `SameAnomalyType` | **0,3** (`SameTypeWeight`) |
| **Poste / Utilisateur (fenêtre courte)** | `host:<host>`, `user:<host>:<user>` | `user:PC-01:alice` | `SameWindow` | **0,3** à **0,5** |

Les indices explicites portés par `SecurityEvent.CorrelationHints` (domaine extrait, hash de fichier téléchargé, PID parent) sont automatiquement fusionnés dans les clés d'indexation.

---

## 3. Fenêtres glissantes

Les événements sont conservés dans l'index de corrélation selon trois horizons temporels (`CorrelationSettings`) :

| Fenêtre | Paramètre | Valeur par défaut | Usage typique |
|---|---|---|---|
| **Courte** | `ShortWindowMinutes` | **5 minutes** | Rafales rapides : BadUSB (USB HID → frappe scriptée → PowerShell), ransomware (`FileBurst`), clic phishing → téléchargement → exécution. |
| **Moyenne** | `MediumWindowMinutes` | **30 minutes** | Campagnes multi-étapes interactives : brute force → connexion réussie → processus suspect, création d'archive → exfiltration. |
| **Longue** | `LongWindowHours` | **24 heures** | Signaux faibles espacés, récurrence sur le même domaine/type de menace, persistance post-installation, clusters actifs exposés au dashboard. |

Les événements dont l'ancienneté dépasse `LongWindowHours` sont évincés de l'index mémoire actif (tout en restant persistés 90 jours dans `Sentinel.Storage`).

---

## 4. Formule de scoring de cluster

Lorsqu'un événement $e_k$ rejoint ou met à jour un cluster $C = \{e_1, e_2, \dots, e_n\}$ relié par un ensemble d'arêtes $L(C)$, le score du cluster est recalculé selon la formule :

$$
\text{ScoreCluster}(C) = \min\!\left(100,\; \max_{i \in C}(s_i) + \sum_{j \in C \setminus \{i^*\}} \left(s_j \times w_{i^*, j} \times f(\Delta t_{i^*, j})\right) + B_{\text{séquence}}(C)\right)
$$

Où :
- $s_i \in [0, 100]$ est le score individuel de l'événement $e_i$, et $i^* = \arg\max_{i \in C} s_i$ est l'événement de score maximal ;
- $w_{i^*, j} \in [0,3;\; 0,8]$ est le **poids du lien** (`SameTypeWeight = 0,3` pour un même type d'anomalie ou une simple proximité temporelle, jusqu'à `SameEntityWeight = 0,8` pour une entité partagée telle que domaine, hash, fichier ou parent PID) ;
- $f(\Delta t)$ est le **facteur de décroissance temporelle exponentielle** piloté par la demi-vie $T_{1/2} = \text{DecayHalfLifeMinutes}$ (par défaut **15 minutes**) :

$$
f(\Delta t) = 2^{-\,\frac{|\Delta t|}{T_{1/2}}} = \exp\!\left(-\ln(2)\,\frac{|\Delta t|}{T_{1/2}}\right)
$$

  - Pour $\Delta t = 0\text{ min}$ : $f(0) = 1{,}00$
  - Pour $\Delta t = 5\text{ min}$ : $f(5) \approx 0{,}79$
  - Pour $\Delta t = 15\text{ min}$ : $f(15) = 0{,}50$
  - Pour $\Delta t = 30\text{ min}$ : $f(30) = 0{,}25$
- $B_{\text{séquence}}(C) \in \{0\} \cup [15, 30]$ est le **bonus de séquence** attribué lorsque l'enchaînement d'événements du cluster correspond partiellement ou totalement à l'une des 7 chaînes d'attaque connues (§6).

### Exemple numérique (phishing progressif)

Considérons trois signaux faibles consécutifs sur le poste `PC-01` dans un intervalle de 2 minutes :
1. $e_1$ (`ClipboardUrl` vers un raccourcisseur `bit.ly`) : $s_1 = 38$ (niveau 1 — Faible).
2. $e_2$ (`LinkClicked` + `DownloadStarted` sur le même domaine, $\Delta t = 1\text{ min}$, même entité $w = 0{,}8$) : $s_2 = 45$ (niveau 1 — Faible).
   - Sans corrélation : $\max(38, 45) = 45$ (aucune alerte administrateur !).
   - Avec corrélation : $45 + 38 \times 0{,}8 \times 2^{-1/15} = 45 + 29{,}0 = 74$ + bonus séquence partielle (+15) $\Rightarrow \mathbf{89}$ (**Niveau 3 — Élevé**, alerte administrateur avant même l'exécution !).
3. $e_3$ (`ProcessStart` de `facture.pdf.exe` issu du téléchargement, $\Delta t = 30\text{ s}$) : score de cluster plafonné à **100** (**Niveau 4 — Critique**, blocage automatique réversible si mode `Active`).

---

## 5. Règle d'escalade précoce (2ᵉ événement)

Conformément à l'objectif central de SENTINEL (§1.1 et §8.2-5) et contrôlée par `CorrelationSettings.EarlyEscalation = true` :

- Dès qu'un **2ᵉ événement similaire** (même `ThreatType != None` ou même entité suspecte) de score $\ge \text{MinEventScore}$ survient dans un même contexte sur la fenêtre active :
  1. Le drapeau `CorrelationCluster.Escalated` passe à `true`.
  2. Le niveau du cluster est **relevé d'un cran** via `ThreatLevels.Raise(level)` (sans dépasser `ThreatLevel.Critical`).
  3. L'administrateur est **alerté immédiatement** (`ResponseDecision.AlertAdmin = true`) si le niveau atteint ou dépasse `Moderate`/`High`, avec une justification explicite mentionnant l'escalade précoce au 2ᵉ événement.

Cette règle permet de détecter une campagne (ex. deux clics suspects, deux anomalies de saisie, deux connexions inhabituelles) **avant** que l'étape finale de compromission ne se réalise.

---

## 6. Les 7 chaînes d'attaque modélisées et mapping MITRE ATT&CK

Chaque chaîne est modélisée comme une séquence ordonnée d'étapes (`AttackChainMatch`). Un bonus progressif (+15 pour correspondance partielle dès 2 étapes significatives, jusqu'à +30 pour correspondance complète) est ajouté au score du cluster, et les identifiants **MITRE ATT&CK** correspondants (issus de `MitreCatalog`) sont attachés au cluster et à l'alerte.

| # | Identifiant / Nom | Type de menace (`ThreatType`) | Séquence d'événements (`EventTypes`) | Bonus max | Techniques MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | **Phishing → exécution** (`chain-phishing-exec`) | `Phishing` / `Malware` | `ClipboardUrl` / `LinkClicked` → `UrlVisited` / `Redirect` → `DownloadStarted` / `FileCreated` (exécutable) → `ProcessStart` → `NetworkConnection` (IP/domaine inconnu) | +30 | `T1566`, `T1566.002`, `T1204`, `T1204.002`, `T1105`, `T1071` |
| 2 | **BadUSB** (`chain-badusb`) | `BadUsb` | `UsbInserted` / `DeviceAdded` (`device.class=HID` ou `device.keyboard=true`) → `TypingStats` (vitesse anormale / faible variance / `typing.injected=true`) → `ProcessStart` (`powershell.exe`, `cmd.exe`, `mshta.exe`) | +30 | `T1200`, `T1056`, `T1059`, `T1059.001`, `T1059.003` |
| 3 | **Ransomware** (`chain-ransomware`) | `Ransomware` | `FileBurst` (rafale de modifications) + hausse d'entropie (`file.entropy` / `burst.entropy.avg > 7,0`) + `FileRenamed` (changements d'extensions massifs) / `ProcessStart` non signé | +30 | `T1486`, `T1059`, `T1204.002` |
| 4 | **Exfiltration** (`chain-exfiltration`) | `Exfiltration` | `FileCreated` (`file.archive=true`, `.zip`/`.7z`/`.rar`) → `NetworkVolume` (volume sortant anormal) + `DnsQuery` / `NetworkConnection` vers domaine rare ou `UsbInserted` (`device.storage=true`) | +25 | `T1560`, `T1041`, `T1052`, `T1071` |
| 5 | **Brute force / intrusion** (`chain-bruteforce`) | `Intrusion` | $N$ × `LogonFailure` (Event ID `4625`) → `LogonSuccess` (`4624`, éventuellement hors horaires habituels) → `ProcessStart` inhabituel ou élevé | +25 | `T1110`, `T1078`, `T1059` |
| 6 | **Persistance** (`chain-persistence`) | `Persistence` | `AppInstalled` / `FileCreated` (non signé) → `StartupEntryAdded` (clé Registre `Run`/`RunOnce`) + `ScheduledTaskCreated` (Planificateur de tâches) | +25 | `T1547`, `T1547.001`, `T1053`, `T1053.005` |
| 7 | **Ingénierie sociale** (`chain-social-eng`) | `SocialEngineering` | `ClipboardUrl` (`url.shortener=true`) ou `LinkClicked` → `UrlVisited` (domaine récent `domain.age.days < 30`) → `DownloadStarted` / `FileCreated` (`file.double.ext=true` ou `file.executable=true`) | +25 | `T1566.002`, `T1036`, `T1036.007`, `T1204`, `T1105` |

### Détection complémentaire d'auto-protection

En marge des 7 chaînes d'attaque, les événements système `AgentTampering`, `IntegrityViolation` ou `AgentStopped` inattendu émis par `Sentinel.Watchdog` sont immédiatement classés `ThreatType.Tampering` et mappés à **`T1562` (*Impair Defenses*)**.

---

## 7. Représentation dans le graphe de corrélation

Chaque cluster est persisté dans `Clusters` et `ClusterLinks`, puis projeté par `GET /api/graph` vers `GraphDto` (rendu localement par Cytoscape.js dans `Sentinel.Admin`) :
- **Nœuds** : événements (`Event`) reliés aux entités extraites (`Process`, `File`, `Domain`, `Ip`, `User`, `Device`, `Host`) et aux nœuds de menace (`Threat`).
- **Arêtes** : relations structurelles (`Spawned`, `ConnectedTo`, `Wrote`, `CopiedFromClipboard`, `OpenedUrl`) et relations de corrélation (`SameDomain`, `SameHash`, `SameEntity`, `SameAnomalyType`, `SameWindow`, `Sequence`, `InvolvedIn`).
- **Explicabilité** : chaque cluster expose `MaxEventScore` (score individuel le plus haut) face à `Score` (score corrélé), permettant de visualiser directement le **gain de corrélation** dans la console et les rapports.
