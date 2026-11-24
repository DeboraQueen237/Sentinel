# Guide administrateur SOC — SENTINEL v2

> Guide opérationnel de la console d'administration **Sentinel.Admin** (`http://127.0.0.1:5200`) et des APIs de gestion v2.

---

## 1. Première connexion et sécurité du compte

1. Ouvrez `http://127.0.0.1:5200` (local uniquement).
2. Créez le compte administrateur unique (`/setup`) avec un mot de passe robuste, scannez le **QR Code 2FA TOTP** (Aegis, Google Authenticator, Bitwarden) et conservez la clé Base32 en lieu sûr.
3. **Protection brute-force** : après **5 échecs consécutifs**, la connexion est verrouillée pendant **15 minutes** (HTTP `429 Too Many Requests`, journalisé dans l'Audit).
4. En haut à droite : basculez la langue (**FR / EN**) et le thème (**Clair / Sombre**).

---

## 2. Les 13 écrans de la console v2

| Section | Écran | Route | Opérations principales |
|---|---|---|---|
| **Supervision** | Vue d'ensemble | `/` | Score global, alertes critiques, courbe 24 h / 7 j / 30 j, santé serveur & Ollama (`qwen2.5-coder:3b`) |
| | Alertes | `/alerts` | Filtrage, détail explicable (MITRE, moteurs, événements), **Approuver / Rejeter (faux positif réversible) / Acquitter / Résoudre** |
| | Graphe de corrélation | `/graph` | Graphe interactif Cytoscape.js, **filtre par tactique MITRE ATT&CK**, récit chronologique du cluster, ventilation des scores par moteur, **bouton Annuler l'action en 1 clic** |
| **Investigation** | Fiches Postes & Entités | `/entities` | Profils postes, utilisateurs, domaines, processus, fichiers, IP *(chaque consultation est journalisée dans l'Audit)* |
| | Actions & blocages | `/actions` | Tickets d'action (`Proposed` → approuver/rejeter, `Executed` → **Annuler en 1 clic**), blocages manuels |
| **Détection v2** | Renseignement | `/intel` | État des flux (abuse.ch, OpenPhish/PhishTank opt-in), nombre d'indicateurs, **rafraîchissement manuel**, recherche instantanée IOC (hash/domaine/URL/IP) via Bloom+SQLite |
| | Règles & Scan | `/rules` | Liste des règles **Sigma** et **YARA**, activation/désactivation à chaud, rechargement, **scan statique à la demande** (YARA + PeNet + ML PE) |
| | Modèle ML | `/ml` | État du classifieur ML.NET PE (`pe-classifier.zip`), version, ROC-AUC, Recall @ 0,1 % FPR, rappel du plafond de sécurité (≤ 35/100) |
| | Canaris | `/canaries` | Inventaire des fichiers leurres anti-ransomware, statut SHA-256, bouton **Vérifier / Redéployer** |
| | Santé agents | `/health` | CPU %, RAM, file d'attente, **statut Microsoft Defender (Temps réel ON/OFF)**, **présence de Sysmon (optionnel)**, état de chaque collecteur |
| **Gouvernance** | Rapports & Évaluation | `/reports` | Export PDF (QuestPDF) / JSON et tableau comparatif A vs B vs C |
| | Paramètres | `/settings` | Mode (`Learning` / `Simulation` / `Active`), seuils 0–4, dossiers surveillés, exclusions, interrupteurs v2 (Defender, Sysmon, Canaris, PowerShell 4104, extrait opt-in, Sigma/YARA/ML), modèle Ollama, rétention |
| | Audit & Intégrité | `/audit` | Journal chaîné SHA-256 + bouton **Vérifier l'intégrité cryptographique** (`GET /api/audit/verify`) |

---

## 3. Maintenance courante

- **Mettre à jour les règles SigmaHQ** (opt-in, licence DRL 1.1) : `.\scripts\update-sigma-rules.ps1`
- **Mettre à jour les règles YARA** : `.\scripts\update-yara-rules.ps1`
- **Entraîner un modèle ML PE local** (depuis un dataset EMBER 2018 légal) : voir [docs/ml-evaluation.md](ml-evaluation.md)
- **Activer PowerShell Script Block Logging (4104)** : `.\scripts\enable-script-logging.ps1` (en administrateur)
- **Configurer une clé API abuse.ch / VirusTotal** : en dev `dotnet user-secrets set "ThreatIntel:AbuseChApiKey" "<clé>" --project src/Sentinel.Server`, en production via `SecretProtector` (DPAPI) — **jamais dans Git ni dans `appsettings.json`**.
