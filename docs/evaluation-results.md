# SENTINEL — Rapport d'évaluation scientifique (Protocole A vs B vs C)

> Généré le **2026-11-22 22:20:31 UTC** — Poste simulé : `WS-EVAL-01`
> **Moteur IA utilisé (B & C)** : DeterministicSimulatedLlmAssessor (analyste IA local simulé déterministe, 0 dépendance réseau)
> *Note méthodologique :* cette exécution repose sur l'évaluateur déterministe local `DeterministicSimulatedLlmAssessor` (sans dépendance réseau). Relancez avec `--ollama --ollama-model qwen2.5-coder:3b` lorsqu'un serveur Ollama local est actif pour mesurer la latence et les scores réels.

## 1. Hypothèse scientifique évaluée (doc §1.2, §8.4, §14.3)

> *La corrélation d'événements individuellement faibles réduit le délai de détection d'une chaîne d'attaque (Time-To-Detect) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*

Trois configurations sont comparées sur exactement les mêmes 11 scénarios d'attaque (v1 + v2) et le même corpus bénin de fond sur 24 heures :
- **(A) Règles + Sigma seules** : `Llm.Enabled = false`, `Correlation.Enabled = false`.
- **(B) Règles + Sigma + IA sans corrélation** : `Llm.Enabled = true`, `Correlation.Enabled = false`.
- **(C) SENTINEL v2 Complet** : `Llm.Enabled = true`, `Correlation.Enabled = true`, `EarlyEscalation = true` (graphe Markovien).

Un scénario est considéré **détecté** dès qu'une décision atteint le niveau **Élevé (≥ 75)** ou déclenche `AlertAdmin = true`.

## 2. Synthèse des métriques agrégées

| Configuration | Scénarios détectés | Rappel | Précision | Faux positifs (FPR) | Évts moy. avant alerte | TTD moyen (s) | Latence moy. (ms) | RAM (Mo) | Appels IA |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **A - Règles + Sigma seules** | 11/11 | 100.0 % | 100.0 % | 0 (0.00 %) | 2.64 | 13.55 s | 0.124 ms | 45.8 Mo | 0 (0.0 %) |
| **B - Règles + Sigma + IA** | 11/11 | 100.0 % | 100.0 % | 0 (0.00 %) | 2.27 | 10.45 s | 0.033 ms | 44.9 Mo | 23 (4.6 %) |
| **C - SENTINEL v2 Complet** | 11/11 | 100.0 % | 100.0 % | 0 (0.00 %) | 1.73 | 6.09 s | 0.051 ms | 47.9 Mo | 23 (4.6 %) |

### Gains mesurés de la configuration (C)

- **Gain Time-To-Detect (C vs A, comparaison appariée sur scénarios détectés par A et C)** : `13.55 s` → `6.09 s`, soit **-55.0 %** (et **-0.91 événements** en moyenne avant l'alerte).
- **Gain Time-To-Detect (C vs B, comparaison appariée sur scénarios détectés par B et C)** : `10.45 s` → `6.09 s`, soit **-41.7 %** (et **-0.55 événements** en moyenne avant l'alerte).
- **Gain de rappel (C vs A)** : `100.0 %` → `100.0 %` (+0 scénario(s) détecté(s) grâce à la corrélation et au contexte).
- **Vérification de la règle du « 2ᵉ événement » (doc §1.1, §8.2-5, §14.2)** : **VALIDÉE (100 % des chaînes multi-étapes alertent dès le 2ᵉ événement)** (moyenne sur les chaînes multi-étapes en config C : `1.80` événements).
- **Taux de faux positifs (corpus bénin de 459 événements)** : `0` FP en (A), `0` FP en (B), `0` FP en (C) — FPR = **0.00 %**.

## 3. Résultats détaillés par scénario et mapping MITRE ATT&CK

| Scénario | Techniques MITRE ATT&CK | (A) Règles seules | (B) Règles + IA | (C) Règles + IA + Corrélation | Chaîne corrélée (C) | Gain TTD (C vs A) |
|---|---|---|---|---|---|---:|
| **1. Phishing → exécution** | `T1566.002`, `T1204`, `T1071` | Evt **#3**/5 — **18.0 s** (pic 100) | Evt **#3**/5 — **18.0 s** (pic 100) | Evt **#2**/5 — **6.0 s** (pic 100) | Phishing → exécution (5/5) | **-66.7 %** (-12.0 s) |
| **2. BadUSB (HID → PowerShell)** | `T1200`, `T1056`, `T1059.001` | Evt **#3**/4 — **5.0 s** (pic 100) | Evt **#3**/4 — **5.0 s** (pic 100) | Evt **#2**/4 — **2.0 s** (pic 100) | Attaque BadUSB (HID → frappe scriptée → shell) (3/3) | **-60.0 %** (-3.0 s) |
| **3. Ransomware simulé** | `T1486` | Evt **#1**/4 — **0.0 s** (pic 87) | Evt **#1**/4 — **0.0 s** (pic 87) | Evt **#1**/4 — **0.0 s** (pic 100) | Activité Ransomware (rafale + entropie + renommages) (3/3) | 0 % (IOC connu) |
| **4. Exfiltration de données** | `T1560`, `T1041`, `T1052` | Evt **#4**/4 — **40.0 s** (pic 93) | Evt **#3**/4 — **26.0 s** (pic 93) | Evt **#2**/4 — **12.0 s** (pic 100) *(escalade)* | Exfiltration de données (archive + transfert externe) (3/3) | **-70.0 %** (-28.0 s) |
| **5. Brute force → intrusion** | `T1110`, `T1078`, `T1059` | Evt **#5**/8 — **32.0 s** (pic 93) | Evt **#3**/8 — **16.0 s** (pic 93) | Evt **#2**/8 — **8.0 s** (pic 100) | Brute force / intrusion (échecs → connexion → exécution) (3/3) | **-75.0 %** (-24.0 s) |
| **6. Persistance** | `T1204`, `T1547.001`, `T1053.005` | Evt **#2**/3 — **15.0 s** (pic 92) | Evt **#2**/3 — **15.0 s** (pic 92) | Evt **#2**/3 — **15.0 s** (pic 100) | Établissement de persistance (installation + démarrage + tâche) (3/3) | **-0.0 %** (-0.0 s) |
| **7. Ingénierie sociale** | `T1566`, `T1566.002`, `T1204.002` | Evt **#4**/4 — **9.0 s** (pic 80) | Evt **#3**/4 — **5.0 s** (pic 88) | Evt **#2**/4 — **3.0 s** (pic 100) | Ingénierie sociale (lien raccourci → domaine récent → exécutable) (3/3) | **-66.7 %** (-6.0 s) |
| **8. Fichier EICAR (IOC)** | `T1204.002` | Evt **#1**/2 — **0.0 s** (pic 100) | Evt **#1**/2 — **0.0 s** (pic 100) | Evt **#1**/2 — **0.0 s** (pic 100) | Signature directe | 0 % (IOC connu) |
| **9. Affaiblissement Defender (v2)** | `T1562.001`, `T1218`, `T1105` | Evt **#2**/4 — **12.0 s** (pic 100) | Evt **#2**/4 — **12.0 s** (pic 100) | Evt **#2**/4 — **12.0 s** (pic 100) | Phishing → exécution (2/5) | **-0.0 %** (-0.0 s) |
| **10. Piège Canari Ransomware (v2)** | `T1486` | Evt **#1**/3 — **0.0 s** (pic 98) | Evt **#1**/3 — **0.0 s** (pic 98) | Evt **#1**/3 — **0.0 s** (pic 100) | Signature directe | 0 % (IOC connu) |
| **11. Script PowerShell 4104 (v2)** | `T1059.001`, `T1027`, `T1562.006`, `T1071` | Evt **#3**/4 — **18.0 s** (pic 97) | Evt **#3**/4 — **18.0 s** (pic 97) | Evt **#2**/4 — **9.0 s** (pic 100) | Signature directe | **-50.0 %** (-9.0 s) |

## 4. Tableau complet (Scénario × Configuration)

| Scénario | Configuration | Détecté | Évts avant alerte | TTD (s) | Score pic | Niveau 1ʳᵉ alerte | Déclencheur | Escalade précoce | Latence (ms) |
|---|---|---|---:|---:|---:|---|---|---|---:|
| 1. Phishing → exécution | A - Règles + Sigma seules | Oui | 3/5 | 18.00 | 100/100 | Critique | Browser/DownloadStarted | Non | 3.423 |
| 2. BadUSB (HID → PowerShell) | A - Règles + Sigma seules | Oui | 3/4 | 5.00 | 100/100 | Critique | Typing/TypingStats | Non | 1.174 |
| 3. Ransomware simulé | A - Règles + Sigma seules | Oui | 1/4 | 0.00 | 87/100 | Élevé | Process/ProcessStart | Non | 0.122 |
| 4. Exfiltration de données | A - Règles + Sigma seules | Oui | 4/4 | 40.00 | 93/100 | Critique | Network/NetworkVolume | Non | 0.044 |
| 5. Brute force → intrusion | A - Règles + Sigma seules | Oui | 5/8 | 32.00 | 93/100 | Élevé | Session/LogonFailure | Non | 0.285 |
| 6. Persistance | A - Règles + Sigma seules | Oui | 2/3 | 15.00 | 92/100 | Critique | Installation/StartupEntryAdded | Non | 0.296 |
| 7. Ingénierie sociale | A - Règles + Sigma seules | Oui | 4/4 | 9.00 | 80/100 | Élevé | Browser/DownloadStarted | Non | 0.044 |
| 8. Fichier EICAR (IOC) | A - Règles + Sigma seules | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.062 |
| 9. Affaiblissement Defender (v2) | A - Règles + Sigma seules | Oui | 2/4 | 12.00 | 100/100 | Critique | Defender/DefenderExclusionAdded | Non | 0.210 |
| 10. Piège Canari Ransomware (v2) | A - Règles + Sigma seules | Oui | 1/3 | 0.00 | 98/100 | Élevé | Process/ProcessStart | Non | 0.170 |
| 11. Script PowerShell 4104 (v2) | A - Règles + Sigma seules | Oui | 3/4 | 18.00 | 97/100 | Critique | Script/ScriptLoggingBypass | Non | 0.054 |
| 1. Phishing → exécution | B - Règles + Sigma + IA | Oui | 3/5 | 18.00 | 100/100 | Critique | Browser/DownloadStarted | Non | 0.069 |
| 2. BadUSB (HID → PowerShell) | B - Règles + Sigma + IA | Oui | 3/4 | 5.00 | 100/100 | Critique | Typing/TypingStats | Non | 0.090 |
| 3. Ransomware simulé | B - Règles + Sigma + IA | Oui | 1/4 | 0.00 | 87/100 | Élevé | Process/ProcessStart | Non | 0.122 |
| 4. Exfiltration de données | B - Règles + Sigma + IA | Oui | 3/4 | 26.00 | 93/100 | Élevé | Network/DnsQuery | Non | 0.050 |
| 5. Brute force → intrusion | B - Règles + Sigma + IA | Oui | 3/8 | 16.00 | 93/100 | Élevé | Session/LogonFailure | Non | 0.049 |
| 6. Persistance | B - Règles + Sigma + IA | Oui | 2/3 | 15.00 | 92/100 | Critique | Installation/StartupEntryAdded | Non | 0.053 |
| 7. Ingénierie sociale | B - Règles + Sigma + IA | Oui | 3/4 | 5.00 | 88/100 | Élevé | Browser/Redirect | Non | 0.051 |
| 8. Fichier EICAR (IOC) | B - Règles + Sigma + IA | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.041 |
| 9. Affaiblissement Defender (v2) | B - Règles + Sigma + IA | Oui | 2/4 | 12.00 | 100/100 | Critique | Defender/DefenderExclusionAdded | Non | 0.042 |
| 10. Piège Canari Ransomware (v2) | B - Règles + Sigma + IA | Oui | 1/3 | 0.00 | 98/100 | Élevé | Process/ProcessStart | Non | 0.033 |
| 11. Script PowerShell 4104 (v2) | B - Règles + Sigma + IA | Oui | 3/4 | 18.00 | 97/100 | Critique | Script/ScriptLoggingBypass | Non | 0.041 |
| 1. Phishing → exécution | C - SENTINEL v2 Complet | Oui | 2/5 | 6.00 | 100/100 | Critique | Browser/UrlVisited | Non | 0.891 |
| 2. BadUSB (HID → PowerShell) | C - SENTINEL v2 Complet | Oui | 2/4 | 2.00 | 100/100 | Critique | Typing/TypingStats | Non | 0.282 |
| 3. Ransomware simulé | C - SENTINEL v2 Complet | Oui | 1/4 | 0.00 | 100/100 | Élevé | Process/ProcessStart | Non | 0.685 |
| 4. Exfiltration de données | C - SENTINEL v2 Complet | Oui | 2/4 | 12.00 | 100/100 | Critique | Device/UsbInserted | Oui (+1 niv.) | 0.287 |
| 5. Brute force → intrusion | C - SENTINEL v2 Complet | Oui | 2/8 | 8.00 | 100/100 | Critique | Session/LogonFailure | Non | 0.588 |
| 6. Persistance | C - SENTINEL v2 Complet | Oui | 2/3 | 15.00 | 100/100 | Critique | Installation/StartupEntryAdded | Non | 0.111 |
| 7. Ingénierie sociale | C - SENTINEL v2 Complet | Oui | 2/4 | 3.00 | 100/100 | Critique | Browser/UrlVisited | Non | 0.233 |
| 8. Fichier EICAR (IOC) | C - SENTINEL v2 Complet | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.078 |
| 9. Affaiblissement Defender (v2) | C - SENTINEL v2 Complet | Oui | 2/4 | 12.00 | 100/100 | Critique | Defender/DefenderExclusionAdded | Non | 0.163 |
| 10. Piège Canari Ransomware (v2) | C - SENTINEL v2 Complet | Oui | 1/3 | 0.00 | 100/100 | Élevé | Process/ProcessStart | Non | 0.189 |
| 11. Script PowerShell 4104 (v2) | C - SENTINEL v2 Complet | Oui | 2/4 | 9.00 | 100/100 | Critique | Script/PowerShellScriptBlock | Non | 0.137 |

## 5. Corpus de trafic bénin et maîtrise des faux positifs

Le corpus bénin comporte **459 événements** simulant une journée complète de **24 heures** (00h00–23h59) :
- Activité bureautique de journée (08h30–17h30) : processus signés Microsoft/Google/Mozilla, domaines habituels, fichiers bureautiques basse entropie, dynamique de saisie humaine (~5 touches/s, σ ≈ 45 ms), cycle de session et erreur isolée de mot de passe.
- Activité de fond sur 24 h (nuit et soirée) : mises à jour Windows/Defender (`MsMpEng.exe`, `UsoClient.exe`), synchronisation `OneDrive.exe`, indexation `SearchIndexer.exe`, résolutions DNS légitimes et blocs PowerShell d'administration non obfusqués.

Sur ce corpus, l'appel sélectif au LLM (bande ambiguë 25–80) n'est sollicité que sur **4.6 %** des événements totaux, garantissant un taux de faux positifs de **0.00 %** et une latence moyenne de **0.051 ms/événement**.

