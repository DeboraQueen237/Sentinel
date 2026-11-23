# Modèle de menace (Threat Model — STRIDE v2)

> Analyse des surfaces d'attaque, menaces, mesures de durcissement et limites assumées de **SENTINEL v2.0.0** (mise à jour Mission 9).

---

## 1. Actifs critiques et frontières de confiance

| Actif | Emplacement | Exigence principale |
|---|---|---|
| Journaux d'événements & d'audit | `%ProgramData%\Sentinel\Data\sentinel.db` | Intégrité cryptographique (chaîne SHA-256), confidentialité |
| Certificats PKI mTLS & clés | `%ProgramData%\Sentinel\Certs\`, `Secrets\` | Confidentialité (DPAPI `LocalMachine` + ACL NTFS `SYSTEM`/`Admins`) |
| Compte administrateur & sessions | `AdminUsers`, `AdminSessions` | PBKDF2 + 2FA TOTP + verrouillage brute-force (`429`) |
| Règles Sigma/YARA, base TI, modèle ML | `%ProgramData%\Sentinel\rules\`, `threat-intel\`, `models\` | Intégrité (ACL NTFS restrictives), résilience au parsing malformé |
| Registre canaris & quarantaine | `%ProgramData%\Sentinel\canaries\`, `Quarantine\` | Discrétion/intégrité des hashes canaris, réversibilité sécurisée |
| Binaires & services Windows | `SentinelAgent`, `SentinelServer`, `SentinelAdmin`, `SentinelWatchdog` | Intégrité SHA-256, détection d'arrêt et de **suppression de service** |
| Pipeline décisionnel & LLM | `Sentinel.Core`, `Sentinel.AI`, Ollama (`qwen2.5-coder:3b`) | Résistance à la prompt injection, décision 100 % déterministe |

---

## 2. Analyse STRIDE v2

| Catégorie | Menace concrète | Cible | Gravité | Mitigation implémentée dans SENTINEL v2 |
|---|---|---|---|---|
| **Spoofing** | Usurpation d'un agent sur le canal gRPC | `AgentGateway` (`:5181`) | Élevée | **mTLS obligatoire** via `SentinelPki` (ECDSA P-256, validation CA + EKU `clientAuth`). |
| **Spoofing** | Brute force sur l'authentification administrateur (`POST /api/auth/login`) | `Sentinel.Server` (`AuthService`) | Élevée | PBKDF2 + 2FA TOTP obligatoire + **verrouillage automatique après 5 échecs consécutifs pendant 15 minutes (HTTP `429 Too Many Requests`, en-tête `Retry-After`, entrée d'audit chaînée)** ; écoute strictement `127.0.0.1`. |
| **Tampering** | Altération de `sentinel.db` (événements ou audit) | `Sentinel.Storage` | Élevée | Chaînes SHA-256 contiguës sérialisées (`HashChainWriter`), vérifiées en $O(1)$ mémoire par `IntegrityVerifier`. |
| **Tampering** | Arrêt, altération binaire ou **suppression** (`sc delete`) d'un service SENTINEL | Services Windows | Élevée | `Sentinel.Watchdog` vérifie l'état, le hash SHA-256 des binaires et détecte explicitement la disparition d'un service du SCM (`AgentTampering` / `IntegrityViolation`, MITRE `T1562`). |
| **Tampering** | Désactivation ou ajout d'exclusions dans Microsoft Defender | `WinDefend` | Critique | `DefenderCollector` surveille WMI + journal `Defender/Operational` (IDs `5001`, `5007`, `5010`, `5012`, `5101`) et génère un événement `Tampering` à score élevé (86–94). |
| **Tampering** | Injection d'instructions via nom de fichier, ligne de commande ou URL (**Prompt injection**) | `Sentinel.AI` / Ollama | Élevée | Délimiteurs explicites `<donnees_non_fiables>`, sortie JSON strictement validée par schéma, LLM dépourvu d'outils/actions, repli déterministe automatique, contournement au-delà de `AmbiguityHigh` (80). |
| **Tampering** | Altération des règles Sigma/YARA, du manifeste d'intégrité ou de la base Threat Intel par un utilisateur local non privilégié | `%ProgramData%\Sentinel\` | Élevée | **Durcissement ACL NTFS (`DirectorySecurityHardener`)** en contexte Service/Administrateur élevé : héritage supprimé, accès réservé à `NT AUTHORITY\SYSTEM` et `BUILTIN\Administrators`. Signature HMAC-SHA256 disponible pour les manifestes. |
| **Tampering** | Empoisonnement de flux Threat Intel ou règles Sigma/YARA malformées (ReDoS, YAML bomb) | `Sentinel.Detection.*`, `Sentinel.ThreatIntel` | Moyenne | Parseurs défensifs avec gestion d'erreurs non fatale par règle, timeouts regex, tailles de fichiers bornées (16–50 Mo), circuit-breaker Polly v8. |
| **Repudiation** | Contestation d'une consultation de fiche, d'un feedback VP/FP ou d'une annulation d'action | Console Admin / API | Moyenne | Journal `AuditEntries` chaîné SHA-256 ; feedback analyste historisé avec identifiant unique et annulation réversible (`RevertFeedback`). |
| **Information Disclosure** | Stockage accidentel de mots de passe, frappes, contenus de documents ou secrets dans scripts PowerShell 4104 | Collecteurs & SQLite | Élevée | Zéro keylogger, zéro lecture de contenu de documents/messageries ; PowerShell 4104 limité aux métadonnées/hash par défaut (extrait opt-in ≤ 300 car. avec caviardage automatique des jetons/mots de passe) ; **test d'intégration automatisé inspectant `sentinel.db`**. |
| **Information Disclosure** | Fuite de clés API Threat Intel (abuse.ch, PhishTank, VirusTotal) ou clés privées PKI | Disque / dépôt Git | Élevée | Zéro secret dans Git ; `dotnet user-secrets` en dev, DPAPI `LocalMachine` (`SecretProtector`) en production. |
| **Denial of Service** | Saturation CPU/disque par scan YARA/PE ou requêtes EF Core cartésiennes | `Sentinel.Agent`, `Sentinel.Server` | Moyenne | Scan statique uniquement événementiel/planifié (jamais scan permanent du disque complet), taille max, timeout, parallélisme borné ; requêtes EF Core multi-inclusions optimisées via `.AsSplitQuery()`. |
| **Denial of Service** | Empoisonnement / faux positif du classifieur ML PE | `Sentinel.ML` | Moyenne | Contribution ML **plafonnée (≤ 35/100)** avec plafond interne dur `50` : ne peut jamais déclencher seul une alerte ou une action de blocage. |
| **Elevation of Privilege** | Exécution arbitraire depuis la console Web ou exploitation de lien symbolique lors de la quarantaine | `Admin` → `Server` → `Agent` | Critique | Liste fermée d'actions typées (`ResponseActionType`), aucun shell distant, validation canonique des chemins, interdiction de quarantaine sur dossiers système. |

---

## 3. Hygiène logicielle et audit des dépendances (Mission 9)

- **Analyse statique .NET** : `<EnableNETAnalyzers>true</EnableNETAnalyzers>` et `<AnalysisLevel>latest-recommended</AnalysisLevel>` activés sur toute la solution (`Directory.Build.props`) — **0 avertissement, 0 erreur**.
- **Vulnérabilités NuGet connues** : gestion centralisée (`Directory.Packages.props`) avec `<CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>` et épinglage explicite de `System.Security.Cryptography.Pkcs` en **`10.0.15`** (corrigeant les avis transitifs `NU1902`/`NU1903` issus de `PeNet`). Audit NuGet : **0 vulnérabilité connue**.

---

## 4. Limites assumées (Ring 3)

Voir [docs/limitations.md](limitations.md) : SENTINEL opère en espace utilisateur/service Windows (`Ring 3`) sans pilote noyau ni fournisseur AMSI COM managé. Un adversaire disposant déjà de privilèges `SYSTEM` ou d'un pilote noyau malveillant reste hors de portée d'un EDR espace utilisateur ; le déploiement de `Sentinel.Server` sur un hôte d'administration distinct reste recommandé pour isoler la base d'audit.
