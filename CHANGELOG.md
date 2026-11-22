# Journal des modifications (CHANGELOG)

Toutes les évolutions notables de **SENTINEL** sont consignées ici selon le format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage sémantique (`SemVer`).

---

## [2.0.0] — En cours de développement (`develop`)

### Planification & Gouvernance
- Audit complet v1 → v2 et plan d'architecture détaillé dans `docs/v2-plan.md`.
- Ajout de `THIRD_PARTY_NOTICES.md` (licences vérifiées de toutes les dépendances, flux de renseignement, règles et outils) et de `SECURITY.md`.
- Adaptation du modèle Ollama local par défaut à `qwen2.5-coder:3b` (modèle installé sur le poste cible).

---

## [1.0.0] — 2026-11-22 (`main`)

### Ajouté
- **Socle partagé (`Sentinel.Shared`)** : schéma normalisé `SecurityEvent` / `ThreatAssessment`, catalogue `MitreCatalog`, contrats REST/SignalR/gRPC/IPC, PKI locale ECDSA P-256 (`SentinelPki`), protection DPAPI (`SecretProtector`), chaîne de hachage SHA-256 (`HashChain`).
- **IA locale (`Sentinel.AI`)** : client HTTP Ollama local avec confinement anti prompt-injection (`<donnees_non_fiables>`), validation stricte JSON, concurrence bornée et backoff exponentiel.
- **Cœur d'analyse (`Sentinel.Core`)** : pré-filtre déterministe, 44 règles nommées MITRE ATT&CK, baseline comportementale Welford, scoring hybride, moteur de corrélation en graphe (7 chaînes d'attaque, escalade au 2ᵉ événement), moteur de décision graduée (niveaux 0–4, modes `Learning`/`Simulation`/`Active`).
- **Stockage (`Sentinel.Storage`)** : EF Core 10 SQLite WAL (14 entités), écriture chaînée SHA-256 (`HashChainWriter`), vérification d'intégrité (`IntegrityVerifier`), purge automatique 90 j / 365 j (`RetentionCleaner`).
- **Serveur (`Sentinel.Server`)** : API REST + SignalR (`:5180`), gRPC mTLS (`:5181`), authentification admin PBKDF2 + 2FA TOTP, constructeur de graphe, rapports QuestPDF et JSON.
- **Composants poste** : `Sentinel.Agent` (6 collecteurs système, outbox SQLite, actions réversibles + quarantaine AES-256-GCM), `Sentinel.Tray` (presse-papiers sans texte brut, rythme de frappe sans touches), `Sentinel.BrowserHost`, `extension/` (Chrome/Edge MV3), `Sentinel.Watchdog`, `Sentinel.Installer` (écran de consentement explicite).
- **Console d'administration (`Sentinel.Admin`)** : Blazor Server sombre/clair responsive avec Cytoscape.js et Chart.js locaux.
- **Évaluation & Tests** : 70 tests unitaires/intégration verts et banc comparatif A vs B vs C (`Sentinel.Simulation`).
