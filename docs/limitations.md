# Limites connues et écarts assumés — SENTINEL v2

> Document de transparence technique recensant les limites structurelles de **SENTINEL v2.0.0** ainsi que les écarts documentés par rapport à un EDR commercial à pilote noyau.

---

## 1. Limites architecturales (espace utilisateur / Ring 3)

1. **Absence de pilote noyau (`Ring 0` / minifiltre / ELAM)** : SENTINEL s'exécute en services Windows (`LocalSystem`) et en session utilisateur. Un rootkit noyau ou un attaquant disposant déjà de privilèges `SYSTEM`/`TrustedInstaller` peut tenter d'aveugler les collecteurs malgré `Sentinel.Watchdog`. **Conservez impérativement Microsoft Defender actif.**
2. **Absence de fournisseur AMSI COM managé** : conformément aux recommandations Microsoft et à la Mission 7, SENTINEL n'enregistre pas de DLL COM AMSI en .NET (risque d'instabilité CLR dans les processus système). La visibilité script passe par PowerShell **Event ID 4104** (Script Block Logging) et ETW `Microsoft-Antimalware-Scan-Interface` en lecture seule.
3. **Pas d'inspection TLS/HTTPS MITM** : le trafic réseau chiffré n'est jamais déchiffré ; seule la télémétrie métadonnées (IP, ports, DNS, volumes, extension navigateur) est analysée.

---

## 2. Écarts techniques documentés en v2.0.0

1. **Bibliothèque native `libyara.dll` non fournie par `dnYara`** : le package NuGet `dnYara 2.1.0` ne redistribue pas `libyara.dll`. En son absence, `YaraScannerService` bascule proprement (sans crash de finaliseur grâce à `NativeLibrary.TryLoad`) sur `ManagedYaraFallbackEngine`, qui supporte les règles de chaînes texte/hex/nocase/wide/ascii et conditions booléennes usuelles, mais **pas** les modules natifs YARA (`pe.*`, `elf.*`, `math.*`). L'analyse PE complète reste assurée en parallèle par `PeStaticAnalyzer` (`PeNet 6.1.2`).
2. **Jeu d'entraînement ML PE synthétique en CI** : les 1,1 million d'échantillons EMBER ne sont jamais commités dans Git. Le modèle généré par `--synthetic` valide uniquement la chaîne technique ; un entraînement local sur **EMBER 2018** (ou équivalent légal) est indispensable avant d'accorder un poids opérationnel au score ML (qui reste dans tous les cas plafonné à ≤ 35/100 et jamais seul décisif).
3. **Latence CPU du modèle Ollama `qwen2.5-coder:3b`** : mesurée honnêtement dans [docs/evaluation-report.md](evaluation-report.md) — sans GPU dédié, les appels JSON structurés peuvent dépasser le timeout de 10–30 s et déclencher le repli déterministe automatique. Le gain de `-55,0 %` sur le TTD reste pleinement garanti par la corrélation Markovienne et Sigma.
4. **Validation en VM Windows 11 vierge** : les tests Atomic Red Team (`scripts/run-atomic-red-team-vm.ps1`) et le cycle complet d'installation/mise à niveau/désinstallation silencieuse MSI (`msiexec /qn`) n'ont pas été exécutés sur la machine de développement afin de préserver son intégrité ; ils doivent être joués par l'opérateur dans une VM isolée avec snapshot.

---

## 3. Licences tierces à vérifier avant usage commercial

Consulter [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) avant toute diffusion commerciale :
- **`QuestPDF` (Community License)** : gratuit/MIT-compatible sous 1 M$ USD de chiffre d'affaires annuel ou usage académique/open-source ; licence commerciale requise au-delà.
- **`SigmaHQ` (DRL 1.1)** : non embarqué, téléchargé à la demande par l'utilisateur.
- **`OpenPhish Community`** : usage non commercial uniquement, désactivé par défaut (opt-in).
- **`Sysmon` (Microsoft Sysinternals)** : redistribution interdite, jamais embarqué.
