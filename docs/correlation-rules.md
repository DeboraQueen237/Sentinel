# Moteur de corrélation avancé et chaînes d'attaque (v2)

> Spécification algorithmique du moteur de corrélation de **SENTINEL v2.0.0** (`Sentinel.Core`), combinant graphe temporel, **modèle de transitions de Markov**, escalade précoce au 2ᵉ événement, récit chronologique et rétroaction analyste réversible (Mission 8).

---

## 1. Évolutions majeures de la v2

1. **Modèle probabiliste de transitions de Markov (`AttackChainMarkovModel`)** :
   - Initialisé par des a priori de transitions malveillantes vs bénignes issus des 7 chaînes v1 + chaînes v2 (`Defender → Process`, `Script → Process/Network`, `Canary → File`, `Browser → Process`, `ThreatIntel → Network/File`).
   - Calcule pour chaque cluster une **probabilité de chaîne malveillante** `ChainProbability` ∈ `[0, 1]` par produit normalisé des transitions chronologiques observées.
   - Ajoute un bonus progressif au score de cluster lorsque `ChainProbability >= 0,60`.
2. **Arêtes temporelles horodatées** : chaque lien `CorrelationLink` conserve son horodatage exact `ObservedAt` permettant de reconstruire l'ordre causal exact de l'attaque.
3. **Récit chronologique & tactiques MITRE ATT&CK (`ClusterNarrativeBuilder`)** :
   - Synthétise automatiquement un récit lisible par un analyste humain (`CorrelationCluster.Narrative`) décrivant la chronologie horodatée, les moteurs ayant contribué et les techniques/tactiques MITRE ATT&CK (`MitreTactics` : *Initial Access*, *Execution*, *Persistence*, *Defense Evasion*, *Credential Access*, *Collection*, *Command and Control*, *Exfiltration*, *Impact*).
4. **Ventilation des contributions par moteur (`ScoreContributions`)** :
   - Chaque `ThreatAssessment` et `CorrelationCluster` expose la contribution individuelle de chaque moteur (`Rules`, `Sigma`, `Yara`, `PeStatic`, `ThreatIntel`, `MlPe`, `Defender`, `Canary`, `Script`, `Baseline`, `Llm`, `Correlation`).
5. **Rétroaction analyste historisée et réversible (`AnalystFeedback`)** :
   - Chaque validation **Vrai Positif (VP)** ou **Faux Positif (FP)** enregistre un `FeedbackId`, un horodatage `RecordedAt` et les deltas appliqués aux poids de transition Markov (`RecordFeedbackDelta`).
   - Un analyste peut annuler une décision erronée via `POST /api/feedback/{id}/revert` (`IThreatPipeline.RevertFeedback`), restaurant exactement les poids antérieurs du modèle de Markov.

---

## 2. Formule de scoring de cluster et escalade précoce

$$
\text{ScoreCluster}(C) = \min\!\left(100,\; \max_{i \in C}(s_i) + \sum_{j \in C \setminus \{i^*\}} \left(s_j \times w_{i^*, j} \times 2^{-\frac{|\Delta t_{i^*,j}|}{T_{1/2}}}\right) + B_{\text{séquence}}(C) + B_{\text{Markov}}(C)\right)
$$

- **Fenêtres glissantes** : courte `5 min`, moyenne `30 min`, longue `24 h`, demi-vie `T_{1/2} = 15 min`.
- **Escalade précoce au 2ᵉ événement** (`EarlyEscalation = true`) : intégralement préservée en v2 — dès le 2ᵉ événement suspect dans un même contexte (`score >= 30`), `Escalated = true` et le niveau du cluster est relevé d'un cran (`ThreatLevels.Raise`), déclenchant une alerte administrateur avant l'étape finale.

---

## 3. Chaînes d'attaque modélisées (v1 + v2)

| # | Chaîne | Catégories / Événements clés | Techniques MITRE ATT&CK |
|---|---|---|---|
| 1 | **Phishing → exécution** | `ClipboardUrl` → `UrlVisited` → `DownloadStarted` → `ProcessStart` → `NetworkConnection` | `T1566.002`, `T1204`, `T1105`, `T1071` |
| 2 | **BadUSB** | `UsbInserted` (`HID`) → `TypingStats` (injecté) → `ProcessStart` (`powershell`/`cmd`) | `T1200`, `T1056`, `T1059.001` |
| 3 | **Ransomware** | `ProcessStart` (non signé) → `FileBurst` / haute entropie / `FileRenamed` / **`CanaryModified`/`CanaryEncrypted`** | `T1486`, `T1490` |
| 4 | **Exfiltration** | `FileCreated` (archive) → `DnsQuery` / `NetworkVolume` / `UsbInserted` (`USBSTOR`) | `T1560`, `T1041`, `T1052` |
| 5 | **Brute force / intrusion** | `LogonFailure` (4625) × N → `LogonSuccess` (4624) → `ProcessStart` | `T1110`, `T1078`, `T1059` |
| 6 | **Persistance** | `AppInstalled` / `FileCreated` → `StartupEntryAdded` → `ScheduledTaskCreated` | `T1547.001`, `T1053.005` |
| 7 | **Ingénierie sociale** | `ClipboardUrl` (raccourcisseur) → `UrlVisited` (domaine récent) → `DownloadStarted` | `T1566.002`, `T1036.007`, `T1204.002` |
| 8 | **Évasion Defender + LOLBin *(v2)*** | `DefenderExclusionAdded` / `DefenderRealtimeDisabled` → `ProcessStart` (`certutil`/`mshta`/`powershell`) | `T1562.001`, `T1218`, `T1105` |
| 9 | **Script obfusqué → C2 *(v2)*** | `PowerShellScriptBlock` (4104 obfusqué/encodé) → `ScriptLoggingBypass` → `NetworkConnection` | `T1059.001`, `T1027`, `T1562.006`, `T1071` |
