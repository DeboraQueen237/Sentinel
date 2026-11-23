# Plan de test et protocole d'évaluation scientifique (v2)

> Plan de validation technique de **SENTINEL v2.0.0** — 179 tests unitaires/intégration + banc comparatif A/B/C sur 11 scénarios et corpus bénin 24 h.

---

## 1. Suite de tests automatisés (`dotnet test Sentinel.slnx`)

| Projet de test | Nb tests | Couverture principale |
|---|---:|---|
| `tests/Sentinel.Agent.Tests` | **37** | Collecteurs Defender (WMI + EventLog XML/JSON, affaiblissement), Sysmon optionnel, dédoublonnage multi-sources, fichiers canari anti-ransomware, visibilité PowerShell 4104 + caviardage secrets, outbox SQLite, réversibilité actions. |
| `tests/Sentinel.Core.Tests` | **37** | Règles v1+v2, baseline Welford, anti prompt-injection (`Sentinel.AI`), modèle de transitions de Markov, feedback VP/FP réversible, récits chronologiques, escalade précoce au 2ᵉ événement, matrice de décision, modes `Learning`/`Simulation`/`Active`. |
| `tests/Sentinel.Detection.Tests` | **91** | Moteur Sigma (55 cas positifs/négatifs + benchmark 1 000 règles × 10 000 événements < 5 s), YARA (`dnYara` + `ManagedYaraFallbackEngine`) + analyse statique PE `PeNet` (15 tests), Threat Intel Polly/SQLite/Bloom/hors-ligne, classifieur ML.NET PE (extraction PE réelle, entraînement/rechargement, AUC, Recall@0,1%FPR, bornage, explicabilité). |
| `tests/Sentinel.Server.Tests` | **14** | Auth PBKDF2 + 2FA TOTP + verrouillage brute-force 429 (5 échecs → 15 min), chaînes SHA-256 concurrentes, `IntegrityVerifier`, `RetentionCleaner`, APIs v1+v2, HMAC manifeste ACL, **test automatisé d'inspection SQLite vérifiant 0 fuite de contenu utilisateur**. |
| **Total** | **179** | **179 / 179 verts (0 avertissement, 0 erreur)** |

---

## 2. Scénarios de simulation (`tests/Sentinel.Simulation`)

11 scénarios bénins/simulés (S1 à S8 v1 + S9 Affaiblissement Defender/LOLBin, S10 Piège Canari anti-ransomware, S11 Script PowerShell 4104 obfusqué) évalués contre un corpus bénin sur **24 heures simulées (459 événements)** dans les configurations A, B et C (en mode déterministe et contre Ollama local `qwen2.5-coder:3b`).

Voir les résultats mesurés complets et l'analyse des limites dans [docs/evaluation-report.md](evaluation-report.md).

---

## 3. Tests Atomic Red Team (VM isolée uniquement)

> [!CAUTION]
> Ne jamais exécuter Atomic Red Team sur la machine de développement ou un poste de production.

Utiliser exclusivement [scripts/run-atomic-red-team-vm.ps1](../scripts/run-atomic-red-team-vm.ps1) dans une **VM Windows 11 isolée sans accès réseau interne** après prise de snapshot :

```powershell
# Vérification sans exécution
.\scripts\run-atomic-red-team-vm.ps1 -DryRun

# Exécution dans une VM isolée uniquement
.\scripts\run-atomic-red-team-vm.ps1 -ConfirmIsolatedVm
```
