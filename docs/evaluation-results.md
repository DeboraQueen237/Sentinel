# SENTINEL — Rapport d'évaluation scientifique (Protocole A vs B vs C)

> Généré le **2026-11-22 07:36:30 UTC** — Poste simulé : `WS-EVAL-01`
> **Moteur IA utilisé (B & C)** : DeterministicSimulatedLlmAssessor (analyste IA local simulé déterministe, 0 dépendance réseau)
> *Note méthodologique :* cette exécution repose sur l'évaluateur déterministe local `DeterministicSimulatedLlmAssessor` (sans dépendance réseau). Relancez avec `--ollama` lorsqu'un serveur Ollama local est actif pour mesurer la latence et les scores d'un LLM réel (`qwen2.5:7b`).

## 1. Hypothèse scientifique évaluée (doc §1.2, §8.4, §14.3)

> *La corrélation d'événements individuellement faibles réduit le délai de détection d'une chaîne d'attaque (Time-To-Detect) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*

Trois configurations sont comparées sur exactement les mêmes 8 scénarios d'attaque et le même corpus bénin de fond :
- **(A) Règles seules** : `Llm.Enabled = false`, `Correlation.Enabled = false`.
- **(B) Règles + IA sans corrélation** : `Llm.Enabled = true`, `Correlation.Enabled = false`.
- **(C) Règles + IA + Corrélation** : `Llm.Enabled = true`, `Correlation.Enabled = true`, `EarlyEscalation = true`.

Un scénario est considéré **détecté** dès qu'une décision atteint le niveau **Élevé (≥ 75)** ou déclenche `AlertAdmin = true`.

## 2. Synthèse des métriques agrégées

| Configuration | Scénarios détectés | Rappel | Précision | Faux positifs (FPR) | Évts moy. avant alerte | TTD moyen (s) | Latence moy. (ms) | RAM (Mo) | Appels IA |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **A - Règles seules** | 7/8 | 87.5 % | 100.0 % | 0 (0.00 %) | 3.57 | 20.43 s | 0.300 ms | 36.9 Mo | 0 (0.0 %) |
| **B - Règles + IA** | 8/8 | 100.0 % | 100.0 % | 0 (0.00 %) | 2.75 | 13.88 s | 0.136 ms | 37.3 Mo | 24 (9.5 %) |
| **C - Règles + IA + Corrélation** | 8/8 | 100.0 % | 100.0 % | 0 (0.00 %) | 1.88 | 6.25 s | 0.173 ms | 38.9 Mo | 24 (9.5 %) |

### Gains mesurés de la configuration (C)

- **Gain Time-To-Detect (C vs A, comparaison appariée sur scénarios détectés par A et C)** : `20.43 s` → `5.00 s`, soit **-75.5 %** (et **-1.71 événements** en moyenne avant l'alerte).
- **Gain Time-To-Detect (C vs B, comparaison appariée sur scénarios détectés par B et C)** : `13.88 s` → `6.25 s`, soit **-55.0 %** (et **-0.88 événements** en moyenne avant l'alerte).
- **Gain de rappel (C vs A)** : `87.5 %` → `100.0 %` (+1 scénario(s) détecté(s) grâce à la corrélation et au contexte).
- **Vérification de la règle du « 2ᵉ événement » (doc §1.1, §8.2-5, §14.2)** : **VALIDÉE (100 % des chaînes multi-étapes alertent dès le 2ᵉ événement)** (moyenne sur les chaînes multi-étapes en config C : `2.00` événements).
- **Taux de faux positifs (corpus bénin de 219 événements)** : `0` FP en (A), `0` FP en (B), `0` FP en (C) — FPR = **0.00 %**.

## 3. Résultats détaillés par scénario et mapping MITRE ATT&CK

| Scénario | Techniques MITRE ATT&CK | (A) Règles seules | (B) Règles + IA | (C) Règles + IA + Corrélation | Chaîne corrélée (C) | Gain TTD (C vs A) |
|---|---|---|---|---|---|---:|
| **1. Phishing → exécution** | `T1566.002`, `T1204`, `T1071` | Evt **#4**/5 — **42.0 s** (pic 91) | Evt **#3**/5 — **18.0 s** (pic 91) | Evt **#2**/5 — **6.0 s** (pic 100) | Phishing → exécution (5/5) | **-85.7 %** (-36.0 s) |
| **2. BadUSB (HID → PowerShell)** | `T1200`, `T1056`, `T1059.001` | Evt **#3**/4 — **5.0 s** (pic 100) | Evt **#3**/4 — **5.0 s** (pic 100) | Evt **#2**/4 — **2.0 s** (pic 100) | Attaque BadUSB (HID → frappe scriptée → shell) (3/3) | **-60.0 %** (-3.0 s) |
| **3. Ransomware simulé** | `T1486` | Evt **#4**/4 — **15.0 s** (pic 86) | Evt **#3**/4 — **9.0 s** (pic 86) | Evt **#2**/4 — **4.0 s** (pic 100) | Activité Ransomware (rafale + entropie + renommages) (3/3) | **-73.3 %** (-11.0 s) |
| **4. Exfiltration de données** | `T1560`, `T1041`, `T1052` | Evt **#4**/4 — **40.0 s** (pic 93) | Evt **#3**/4 — **26.0 s** (pic 93) | Evt **#2**/4 — **12.0 s** (pic 100) *(escalade)* | Exfiltration de données (archive + transfert externe) (3/3) | **-70.0 %** (-28.0 s) |
| **5. Brute force → intrusion** | `T1110`, `T1078`, `T1059` | Evt **#5**/8 — **32.0 s** (pic 93) | Evt **#3**/8 — **16.0 s** (pic 93) | Evt **#2**/8 — **8.0 s** (pic 100) | Brute force / intrusion (échecs → connexion → exécution) (3/3) | **-75.0 %** (-24.0 s) |
| **6. Persistance** | `T1204`, `T1547.001`, `T1053.005` | Non détecté (pic 64) | Evt **#3**/3 — **32.0 s** (pic 79) | Evt **#2**/3 — **15.0 s** (pic 100) | Établissement de persistance (installation + démarrage + tâche) (3/3) | **Détecté (manqué par A)** |
| **7. Ingénierie sociale** | `T1566`, `T1566.002`, `T1204.002` | Evt **#4**/4 — **9.0 s** (pic 80) | Evt **#3**/4 — **5.0 s** (pic 88) | Evt **#2**/4 — **3.0 s** (pic 100) | Ingénierie sociale (lien raccourci → domaine récent → exécutable) (3/3) | **-66.7 %** (-6.0 s) |
| **8. Fichier EICAR (IOC)** | `T1204.002` | Evt **#1**/2 — **0.0 s** (pic 100) | Evt **#1**/2 — **0.0 s** (pic 100) | Evt **#1**/2 — **0.0 s** (pic 100) | Signature directe | 0 % (IOC connu) |

## 4. Tableau complet (Scénario × Configuration)

| Scénario | Configuration | Détecté | Évts avant alerte | TTD (s) | Score pic | Niveau 1ʳᵉ alerte | Déclencheur | Escalade précoce | Latence (ms) |
|---|---|---|---:|---:|---:|---|---|---|---:|
| 1. Phishing → exécution | A - Règles seules | Oui | 4/5 | 42.00 | 91/100 | Critique | Process/ProcessStart | Non | 1.495 |
| 2. BadUSB (HID → PowerShell) | A - Règles seules | Oui | 3/4 | 5.00 | 100/100 | Critique | Typing/TypingStats | Non | 3.417 |
| 3. Ransomware simulé | A - Règles seules | Oui | 4/4 | 15.00 | 86/100 | Élevé | File/FileBurst | Non | 0.268 |
| 4. Exfiltration de données | A - Règles seules | Oui | 4/4 | 40.00 | 93/100 | Critique | Network/NetworkVolume | Non | 0.226 |
| 5. Brute force → intrusion | A - Règles seules | Oui | 5/8 | 32.00 | 93/100 | Élevé | Session/LogonFailure | Non | 0.688 |
| 6. Persistance | A - Règles seules | **Non** | — | — | 64/100 | — | — | Non | 0.411 |
| 7. Ingénierie sociale | A - Règles seules | Oui | 4/4 | 9.00 | 80/100 | Élevé | Browser/DownloadStarted | Non | 0.063 |
| 8. Fichier EICAR (IOC) | A - Règles seules | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.064 |
| 1. Phishing → exécution | B - Règles + IA | Oui | 3/5 | 18.00 | 91/100 | Élevé | Browser/DownloadStarted | Non | 0.430 |
| 2. BadUSB (HID → PowerShell) | B - Règles + IA | Oui | 3/4 | 5.00 | 100/100 | Critique | Typing/TypingStats | Non | 0.201 |
| 3. Ransomware simulé | B - Règles + IA | Oui | 3/4 | 9.00 | 86/100 | Élevé | File/FileRenamed | Non | 0.156 |
| 4. Exfiltration de données | B - Règles + IA | Oui | 3/4 | 26.00 | 93/100 | Élevé | Network/DnsQuery | Non | 0.204 |
| 5. Brute force → intrusion | B - Règles + IA | Oui | 3/8 | 16.00 | 93/100 | Élevé | Session/LogonFailure | Non | 0.193 |
| 6. Persistance | B - Règles + IA | Oui | 3/3 | 32.00 | 79/100 | Élevé | Installation/ScheduledTaskCreated | Non | 0.112 |
| 7. Ingénierie sociale | B - Règles + IA | Oui | 3/4 | 5.00 | 88/100 | Élevé | Browser/Redirect | Non | 0.143 |
| 8. Fichier EICAR (IOC) | B - Règles + IA | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.072 |
| 1. Phishing → exécution | C - Règles + IA + Corrélation | Oui | 2/5 | 6.00 | 100/100 | Critique | Browser/UrlVisited | Non | 2.288 |
| 2. BadUSB (HID → PowerShell) | C - Règles + IA + Corrélation | Oui | 2/4 | 2.00 | 100/100 | Critique | Typing/TypingStats | Non | 0.551 |
| 3. Ransomware simulé | C - Règles + IA + Corrélation | Oui | 2/4 | 4.00 | 100/100 | Critique | File/FileModified | Non | 1.811 |
| 4. Exfiltration de données | C - Règles + IA + Corrélation | Oui | 2/4 | 12.00 | 100/100 | Critique | Device/UsbInserted | Oui (+1 niv.) | 0.622 |
| 5. Brute force → intrusion | C - Règles + IA + Corrélation | Oui | 2/8 | 8.00 | 100/100 | Critique | Session/LogonFailure | Non | 0.254 |
| 6. Persistance | C - Règles + IA + Corrélation | Oui | 2/3 | 15.00 | 100/100 | Critique | Installation/StartupEntryAdded | Non | 0.196 |
| 7. Ingénierie sociale | C - Règles + IA + Corrélation | Oui | 2/4 | 3.00 | 100/100 | Critique | Browser/UrlVisited | Non | 0.410 |
| 8. Fichier EICAR (IOC) | C - Règles + IA + Corrélation | Oui | 1/2 | 0.00 | 100/100 | Critique | File/FileCreated | Non | 0.114 |

## 5. Corpus de trafic bénin et maîtrise des faux positifs

Le corpus bénin comporte **219 événements** simulant une journée de travail typique (08h30–17h30) :
- Processus signés Microsoft, Google et Mozilla (`WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`, `chrome.exe`, `msedge.exe`, `firefox.exe`, `Teams.exe`, `Code.exe`).
- Navigation et connexions HTTPS vers des domaines habituels (`github.com`, `microsoft.com`, `office.com`, `wikipedia.org`, `stackoverflow.com`, `intranet.entreprise.local`).
- Créations et modifications de fichiers bureautiques basse entropie (`.docx`, `.xlsx`, `.pdf`, `.txt`, `.pptx`, `.csv`, entropie 3.8–5.4 bits/octet).
- Dynamique de saisie humaine normale (~5 touches/s, écart-type ~45 ms) établissant la baseline de Welford.
- Cycle de session normal (ouverture à 09h00, verrouillage/déverrouillage, fermeture à 17h30) et une erreur isolée de mot de passe en journée.

Sur ce corpus, l'appel sélectif au LLM (bande ambiguë 25–80) n'est sollicité que sur **9.5 %** des événements totaux, garantissant un taux de faux positifs de **0.00 %** et une latence moyenne de **0.173 ms/événement**.

