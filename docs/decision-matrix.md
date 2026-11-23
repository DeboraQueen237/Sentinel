# Matrice de décision graduée et réversibilité (v2)

> Spécification du moteur de décision déterministe de **SENTINEL v2.0.0** (`Sentinel.Core`), intégrant les signaux multi-moteurs v2 et les garanties de réversibilité.

---

## 1. Principe de décision 100 % déterministe

Dans SENTINEL v2, **seul `DecisionEngine` décide d'une action** :
- Le LLM local (Ollama `qwen2.5-coder:3b`) ne déclenche jamais d'action ; il enrichit uniquement la bande ambiguë (`25–80`) avec repli déterministe automatique.
- Le classifieur **ML PE (`Sentinel.ML`)** est strictement plafonné à `MlSettings.MaxScoreContribution` (**35/100** par défaut, plafond dur interne `50`) : **il ne peut jamais atteindre seul le seuil Modéré (55), Élevé (75) ou Critique (90)**.
- Le score effectif est `max(score_événement_multi_moteurs, score_cluster_Markov)` éventuellement relevé par l'escalade précoce au 2ᵉ événement.

---

## 2. Échelle des niveaux de menace (0–4)

| Niveau (`ThreatLevel`) | Plage par défaut | Décision | Effet principal |
|---|---|---|---|
| `0 — Info` | `0 – 29` | Automatique passif | Journalisation seule (`LogOnly`) |
| `1 — Low` | `30 – 54` | Automatique passif | Journalisation + indexation corrélation (`MarkForCorrelation`) |
| `2 — Moderate` | `55 – 74` | Semi-passif | Sensibilisation utilisateur (`NotifyUser`) + `EnhancedMonitoring` |
| `3 — High` | `75 – 89` | **Décision humaine requise** | Alerte admin + actions créées en `Proposed` (approbation explicite) |
| `4 — Critical` | `90 – 100` | **Blocage automatique réversible** | En mode `Active` : exécution réversible (`Pending → Executed`) + alerte critique. En `Learning`/`Simulation` : `Simulated`. |

---

## 3. Déclencheurs v2 haute priorité et matrice d'actions

| Source / Menace v2 | Score typique | Niveau | Réponse en mode `Active` (toutes réversibles) |
|---|---|---|---|
| **Fichier canari touché / chiffré (M6)** (`CanaryModified`, `CanaryEncrypted`, `CanaryRenamed`, `CanaryDeleted`) | **94 – 98** | `Critical` (4) | `KillProcess` (si identifié) + `IsolateNetwork` + `ProtectFolders` + alerte critique immédiate (tickets réversibles). |
| **Affaiblissement Microsoft Defender (M1)** (`DefenderRealtimeDisabled`, `DefenderServiceStopped`, `DefenderExclusionAdded`) | **86 – 94** | `High` / `Critical` | Alerte critique `Tampering` (`T1562.001`), vérification d'intégrité, jamais exclu par `EventPreFilter`. |
| **Détection Microsoft Defender (M1)** (`DefenderThreatDetected`) | **88 – 94** | `High` / `Critical` | Corrélation immédiate avec l'arbre processus/réseau/fichier + proposition/exécution de confinement complémentaire. |
| **Indicateur Threat Intel connu (M4)** (`ThreatIntelMatch` : MalwareBazaar, URLhaus, ThreatFox, Feodo) | **90 – 96** | `Critical` (4) | Blocage immédiat réversible (`BlockDomain` / `BlockIp` / `QuarantineFile`) avec justification sourcée (« listé par URLhaus le … »). |
| **Règle Sigma critique/élevée (M2)** ou **Match YARA (M3)** | **60 – 95** | `Moderate` à `Critical` | Alimente `HybridScorer` avec tags MITRE ATT&CK et contribue à la corrélation de cluster. |
| **Script PowerShell 4104 bypass / téléchargement-exécution (M7)** | **56 – 88** | `Moderate` à `High` | Corrélé avec le processus parent et les connexions sortantes ; escalade critique sur séquence multi-étapes. |
| **Classifieur ML PE (M5)** | **0 – 35** *(borné)* | Signal auxiliaire uniquement | Ne déclenche jamais d'action seul ; renforce la confiance lorsqu'il coïncide avec PE anomalies / Sigma / corrélation. |

La matrice v1 complète (`Phishing`, `Malware`, `Ransomware`, `BadUsb`, `Exfiltration`, `Intrusion`, `SocialEngineering`, `Persistence`, `Anomaly`, `Tampering`) reste intégralement active.

---

## 4. Réversibilité en 1 clic et garde-fous anti-faux-positifs

- **Ticket d'action obligatoire** : chaque exécution capture `RevertStateJson` avant modification système (quarantaine chiffrée, règle pare-feu `Sentinel-Block-*`, lignes `hosts`, PnP, ACL dossiers, compte verrouillé) et s'annule en un clic via `POST /api/actions/{id}/revert` (accessible depuis **Actions & blocages** et directement depuis le panneau du **Graphe de corrélation**).
- **Interdiction absolue de suppression définitive automatique**.
- **Mode `Learning` par défaut (7 jours)** à l'installation, mode `Simulation`, exclusions configurables (`MsMpEng.exe`, binaires SENTINEL) et **feedback analyste VP/FP historisé et réversible** (`POST /api/feedback/{id}/revert`) qui ajuste dynamiquement la baseline et les probabilités de transition Markov.
