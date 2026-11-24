# Avis de licences tierces — SENTINEL (THIRD_PARTY_NOTICES)

Ce document recense l'ensemble des bibliothèques logicielles, outils de build, jeux de règles et flux de renseignement utilisés ou pris en charge par **SENTINEL**, leurs licences vérifiées et leurs conditions de redistribution.

> **Règle de conformité** : tout composant dont la licence interdit la redistribution ou l'usage commercial n'est **jamais** embarqué dans le dépôt ni dans l'installateur ; il est uniquement détecté ou téléchargeable en option par l'utilisateur.

---

## 1. Bibliothèques .NET (packages NuGet)

| Package | Version | Licence SPDX | Usage dans SENTINEL | Redistribution |
|---|---|---|---|---|
| `Google.Protobuf` | 3.36.2 | BSD-3-Clause | Sérialisation Protobuf (gRPC) | Embarqué |
| `Grpc.AspNetCore` / `Grpc.Net.Client` / `Grpc.Core.Api` / `Grpc.Tools` | 2.85.0 | Apache-2.0 | Transport gRPC mTLS Agent ↔ Serveur | Embarqué (`Tools` build-only) |
| `Microsoft.EntityFrameworkCore.Sqlite` / `Design` | 10.0.15 | MIT | Persistance SQLite WAL / PostgreSQL | Embarqué |
| `Microsoft.Data.Sqlite` | 10.0.15 | MIT | Outbox Agent & base Threat Intel | Embarqué |
| `Microsoft.Extensions.Hosting` / `WindowsServices` / `Http` / `Http.Resilience` | 10.0.15 / 10.11.1 | MIT | Hébergement, services Windows, résilience HTTP | Embarqué |
| `Microsoft.AspNetCore.SignalR.Client` | 10.0.15 | MIT | Temps réel Console Admin | Embarqué |
| `Microsoft.Diagnostics.Tracing.TraceEvent` | 3.2.8 | MIT | Collecte ETW Windows (Process, TCPIP, DNS, AMSI) | Embarqué |
| `System.Management` / `System.Diagnostics.EventLog` / `System.Security.Cryptography.ProtectedData` | 10.0.15 | MIT | WMI, EventLog, DPAPI | Embarqué |
| `Serilog.AspNetCore` / `Extensions.Hosting` / `Sinks.File` / `Sinks.Console` | 10.0.0 / 7.0.0 / 6.1.1 | Apache-2.0 | Journalisation structurée | Embarqué |
| `Otp.NET` | 1.4.1 | MIT | Authentification 2FA TOTP (RFC 6238) | Embarqué |
| `QRCoder` | 1.9.0 | MIT | Génération locale du QR Code TOTP | Embarqué |
| `QuestPDF` | 2026.9.2 | **QuestPDF Community License** *(MIT-compatible si chiffre d'affaires annuel < 1 M$ USD, usage académique ou open-source ; licence commerciale requise au-delà)* | Génération des rapports PDF | Embarqué — **vérifier seuil commercial avant diffusion commerciale** |
| `YamlDotNet` | 18.1.0 | MIT | Parser YAML du moteur Sigma (M2) | Embarqué |
| `PeNet` | 6.1.2 | Apache-2.0 | Analyse statique PE & extraction features EMBER (M3, M5) | Embarqué |
| `dnYara` (+ `libyara`) | 2.1.0 | Apache-2.0 (`dnYara`) / BSD-3-Clause (`libyara`) | Moteur de scan YARA (M3, avec repli géré) | Embarqué |
| `Polly` | 8.9.1 | BSD-3-Clause | Retry, timeout, circuit breaker Threat Intel (M4) | Embarqué |
| `Microsoft.ML` / `Microsoft.ML.FastTree` | 5.0.1 | MIT | Classifieur ML de fichiers PE (M5) | Embarqué |
| `xUnit` / `xunit.runner.visualstudio` / `Microsoft.NET.Test.Sdk` / `coverlet.collector` | 2.9.3 / 3.1.5 / 18.12.0 / 10.1.1 | Apache-2.0 / MIT | Tests automatisés (hors binaire distribué) | Dev/Test uniquement |
| `FluentAssertions` | 7.2.0 | Apache-2.0 *(v7.x est la dernière branche Apache-2.0 ; v8+ est passée en licence commerciale Xceed — SENTINEL reste volontairement épinglé en 7.2.0)* | Assertions de tests (hors binaire distribué) | Dev/Test uniquement |

---

## 2. Bibliothèques JavaScript locales (`Sentinel.Admin/wwwroot/lib/`)

| Bibliothèque | Version | Licence SPDX | Usage |
|---|---|---|---|
| `Cytoscape.js` | 3.30.4 | MIT | Graphe interactif de corrélation (servi localement, zéro CDN) |
| `Chart.js` | 4.4.7 | MIT | Courbes temporelles, répartitions et graphiques TTD (servi localement) |

---

## 3. Outils de build et d'empaquetage

| Outil | Version | Licence | Redistribution |
|---|---|---|---|
| `WiX Toolset` (`WixToolset.Sdk` / `wix`) | 5.0.2 | MS-RL (Microsoft Reciprocal License) | Outil de build uniquement (non inclus dans le code applicatif) |

---

## 4. Règles, flux de renseignement, jeux de données et outils externes

| Source | Licence / Conditions d'usage | Embarqué dans SENTINEL ? | Modalité d'utilisation |
|---|---|---|---|
| **Règles Sigma de démonstration SENTINEL** (`rules/sigma/*.yml`) | MIT (écrites par le projet) | **Oui** (14 règles originales) | Incluses par défaut |
| **SigmaHQ Official Rules** (`github.com/SigmaHQ/sigma`) | **DRL 1.1** (Detection Rule License) | **Non** | Téléchargeable à la demande par l'utilisateur via `scripts/update-sigma-rules.ps1` |
| **Règles YARA de démonstration SENTINEL** (`rules/yara/*.yar`) | MIT (écrites par le projet) | **Oui** (règles originales EICAR & scripts) | Incluses par défaut |
| **abuse.ch** (MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker) | **CC0 1.0** (Domaine public ; en-tête `Auth-Key` gratuit requis sur les APIs JSON depuis 2025) | **Non** (flux entrant à la demande) | Téléchargé localement dans SQLite ; clé stockée via `user-secrets`/DPAPI |
| **OpenPhish Community Feed** | **Usage non commercial uniquement** (licence commerciale payante pour entreprises) | **Non** | **Désactivé par défaut**, opt-in explicite avec avertissement de licence |
| **PhishTank** | Gratuit avec attribution (limitation de débit sans clé API) | **Non** | Opt-in avec clé utilisateur |
| **VirusTotal API v3** | Conditions d'usage VirusTotal (API publique non commerciale, quota strict) | **Non** | **Strictly on-demand uniquement** par hash (jamais d'envoi de fichier), clé fournie par l'utilisateur |
| **EMBER Dataset** (Endgame / Elastic) | MIT (features & métadonnées PE, aucun binaire malveillant) | **Non** (volumineux) | Documenté dans `docs/ml-evaluation.md` ; jeu synthétique minimal utilisé pour CI |
| **Sysmon** (Microsoft Sysinternals) | Licence logicielle Sysinternals (**redistribution interdite**) | **Jamais embarqué** | Détecté automatiquement s'il est déjà installé par l'administrateur |
| **Atomic Red Team** (Red Canary) | MIT | **Non** | Scripts de test documentés **pour VM isolée uniquement** |
| **Ollama & modèle `qwen2.5-coder:3b`** | MIT (Ollama) / Apache-2.0 (Qwen 2.5 Coder 3B) | **Non** | Détecté localement sur `http://localhost:11434` ; aucun téléchargement automatique sans accord |
