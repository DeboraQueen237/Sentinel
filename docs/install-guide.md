# Guide d'installation et de déploiement — SENTINEL v2

> Installation Windows 10/11 x64 via **MSI WiX v5**, **Assistant graphique WinForms**, ou **Archive portable**.

---

## 1. Modes d'installation disponibles

| Mode | Livrable | Usage recommandé |
|---|---|---|
| **Installateur Windows MSI (WiX v5)** | `dist/SentinelSetup-2.0.0.msi` | Déploiement standard & entreprise (`msiexec`, GPO/Intune, mise à niveau en place, désinstallation propre) |
| **Assistant graphique / CLI WinForms** | `Sentinel.Installer.exe` | Installation guidée interactive avec écran de consentement explicite, diagnostic Defender/Sysmon/Ollama et choix des composants |
| **Archive portable x64** | `dist/SentinelPortable-2.0.0.zip` | Test rapide ou démonstration sans installation de services Windows |

Vérifiez toujours l'empreinte SHA-256 avant déploiement à l'aide de `dist/SHA256SUMS.txt` :

```powershell
Get-FileHash .\dist\SentinelSetup-2.0.0.msi -Algorithm SHA256
```

---

## 2. Installation via MSI (`SentinelSetup-2.0.0.msi`)

```powershell
# Installation interactive (droits Administrateur requis)
msiexec /i dist\SentinelSetup-2.0.0.msi

# Installation silencieuse avec journalisation
msiexec /i dist\SentinelSetup-2.0.0.msi /qn /l*v sentinel-install.log

# Mise à niveau en place (MajorUpgrade automatique via UpgradeCode stable)
msiexec /i dist\SentinelSetup-2.0.1.msi /qn

# Désinstallation propre
msiexec /x dist\SentinelSetup-2.0.0.msi /qn
```

Le MSI déploie les binaires dans `%ProgramFiles%\Sentinel`, copie les règles de démonstration Sigma/YARA, configure les services Windows (`SentinelServer`, `SentinelAdmin`, `SentinelAgent`, `SentinelWatchdog`) avec récupération automatique sur panne, crée le raccourci **SENTINEL Dashboard** (`http://127.0.0.1:5200`) et enregistre le démarrage automatique de `Sentinel.Tray`.

---

## 3. Installation interactive guidée (`Sentinel.Installer.exe`)

Lancez `Sentinel.Installer.exe` en tant qu'Administrateur :
1. **Diagnostic environnement** : vérifie automatiquement **Microsoft Defender** (avertissement si désactivé), **Sysmon** (informatif, jamais embarqué), **Ollama** local + modèles déjà installés et **RAM du poste**.
2. **Consentement explicite obligatoire** : présente la liste fermée des données et exclusions ; enregistre la preuve signée SHA-256 dans `%ProgramData%\Sentinel\Data\consent.json`.
3. **Configuration** : sélection des composants, activation des fichiers canaris, règles Sigma/YARA déployées dans `%ProgramData%\Sentinel\rules\`, durcissement ACL NTFS (`SYSTEM` + `Administrateurs`), règles pare-feu locales (boucle `5180`/`5200`, gRPC `5181`), mode **Apprentissage (7 jours)** par défaut.
4. **Désinstallation** : `Sentinel.Installer.exe --uninstall` (conserve `%ProgramData%\Sentinel` par défaut) ou `Sentinel.Installer.exe --uninstall --delete-data` pour purger également les données locales.

---

## 4. IA locale Ollama (optionnelle — jamais téléchargée automatiquement)

SENTINEL détecte automatiquement Ollama sur `http://localhost:11434`. Recommandation selon la RAM du poste :

| RAM du poste | Modèle recommandé | Commande manuelle utilisateur |
|---|---|---|
| **≤ 8 Go** | `qwen2.5-coder:1.5b` ou `phi3:mini` | `ollama pull qwen2.5-coder:1.5b` |
| **8 – 16 Go** *(défaut v2)* | **`qwen2.5-coder:3b`** (1,9 Go) | `ollama pull qwen2.5-coder:3b` |
| **≥ 16 Go + GPU** | `qwen2.5:7b` | `ollama pull qwen2.5:7b` |

> Si Ollama n'est pas installé ou indisponible, SENTINEL fonctionne intégralement sur ses 7 autres moteurs déterministes sans perte de stabilité.

---

## 5. Construction depuis les sources

```powershell
# Build complet reproductible (Restore + Release + Tests + Publish win-x64 + WiX v5 MSI + Portable ZIP + SHA256SUMS)
.\build\build.ps1

# Signature Authenticode optionnelle (certificat production ou auto-signé dev uniquement)
.\build\sign.ps1 -Path dist\SentinelSetup-2.0.0.msi -SelfSignedDev
```
