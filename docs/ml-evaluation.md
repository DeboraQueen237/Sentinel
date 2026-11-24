# SENTINEL v2 — Évaluation du classifieur ML de fichiers PE (Mission 5)

> **Statut** : Implémentation complète (`Sentinel.ML` + `Sentinel.ML.Trainer` + tests unitaires `MlClassifierTests`).
> **Avertissement essentiel** : Les métriques présentées ci-dessous pour le modèle `2.0.0-synthetic` sont mesurées sur un **jeu de données synthétique** dédié aux tests unitaires et à la validation de l'architecture. Elles **ne représentent pas** des performances sur malwares réels en production. Pour un usage réel, l'utilisateur doit entraîner le modèle localement sur un corpus légal externe tel qu'**EMBER 2018** (jamais commité dans le dépôt).

---

## 1. Rôle du Machine Learning dans SENTINEL v2

Dans l'architecture de défense en profondeur de SENTINEL v2, le classifieur statique ML sur binaires **Portable Executable (PE)** constitue un **signal complémentaire et borné**, jamais un oracle autonome :

- **Contribution strictement plafonnée** : `PeMlClassifierService.ComputeBoundedScoreContribution` borne la contribution au score d'événement à `MlSettings.MaxScoreContribution` (**35 / 100** par défaut), avec un plafond de sécurité absolu interne `AbsoluteSafetyScoreCeiling = 50`, strictement inférieur au seuil `ThreatThresholds.Moderate` (**55**), `High` (**75**) et `Critical` (**90**).
- **Jamais seul décisif** : Même à probabilité malveillante `1.00`, le classifieur ML seul ne peut déclencher ni alerte modérée/élevée/critique, ni quarantaine, ni isolement réseau, ni arrêt de processus. Il doit être corroboré par d'autres moteurs (règles Sigma, YARA, Threat Intelligence, Microsoft Defender, fichiers canaris, corrélation comportementale de Markov ou analyse LLM locale).
- **Fonctionnement 100 % hors-ligne et dégradé gracieux** : Si `pe-classifier.zip` est absent ou corrompu, `PeMlClassifierService` reste opérationnel en mode non chargé (`ModelLoaded = false`, contribution `0`) sans perturber le pipeline d'analyse statique.
- **Confidentialité stricte** : L'extracteur de caractéristiques ne conserve **aucun contenu textuel** extrait du binaire (uniquement des compteurs statistiques calculés dans un tampon éphémère sur pile immédiatement effacé via `scratch.Clear()`).

---

## 2. Architecture logicielle

| Composant | Emplacement | Rôle |
|---|---|---|
| **Vecteur fixe & schéma ML.NET** | `src/Sentinel.ML/PeFeatureVector.cs` | 51 caractéristiques numériques finies (`PeFeatureVector`), constantes d'indices (`PeFeatureIndex`), ligne ML.NET (`PeTrainingSample`). |
| **Extracteur PE EMBER-like** | `src/Sentinel.ML/PeFeatureExtractor.cs` | Analyse PE via **PeNet 6.1.2** + lecture bornée (`16 Mio` par défaut, `FileShare.ReadWrite \| FileShare.Delete`), entropie par section, histogramme d'octets, statistiques de chaînes. |
| **Chargeurs de datasets** | `src/Sentinel.ML/PeDatasetLoader.cs` | Ingestion directe de fichiers **EMBER 2018 JSONL** (`--ember-jsonl`), JSONL plat et **CSV** (`--csv`), avec exclusion automatique des entrées non étiquetées (`label == -1`). |
| **Générateur synthétique** | `src/Sentinel.ML/SyntheticPeDatasetGenerator.cs` | Génération déterministe (graine fixe) de profils bénin-like et malveillant-like avec chevauchement contrôlé et séparation stratifiée 80/20 pour CI/tests. |
| **Entraîneur & évaluateur** | `src/Sentinel.ML/PeClassifierTrainer.cs` | Entraînement **ML.NET FastTree** (`FastTreeBinaryTrainer`, GBDT + calibration de Platt), calcul ROC-AUC, Recall @ 0,1 % FPR, F1, Précision, seuil calibré, sauvegarde versionnée `.zip` + `.meta.json`. |
| **Service d'inférence & explicabilité** | `src/Sentinel.ML/PeMlClassifierService.cs` | Inférence thread-safe (verrou sur `PredictionEngine`), explication locale via `CalculateFeatureContribution` de ML.NET (repli z-score si indisponible), plafonnement de score, `GetStatus()` -> `MlModelStatusDto`. |
| **Outil console d'entraînement** | `src/Sentinel.ML.Trainer/Program.cs` | CLI autonome `--synthetic`, `--csv`, `--ember-jsonl`, `--inspect`, `--output`, `--help`. |
| **Tests unitaires** | `tests/Sentinel.Detection.Tests/MlClassifierTests.cs` | Validation sur binaire PE réel (`Sentinel.Shared.dll`), reproductibilité synthétique, entraînement/rechargement `.zip`, métriques, explicabilité, plafonnement et concurrence. |

---

## 3. Spécification des 51 caractéristiques statiques (inspirées d'EMBER)

Le vecteur fixe exposé dans `PeFeatureExtractor.FeatureNames` regroupe 51 variables explicables inspirées du benchmark **EMBER** (*Endgame Malware BEnchmark for Research*, Anderson & Roth, 2018), condensées pour rester rapides (< quelques millisecondes par binaire), interprétables en SOC et adaptées à un arbre boosté sur poste Windows :

### 3.1 En-tête PE & métadonnées générales (indices 0–10)

| Indice | Nom | Type / Domaine | Intérêt de détection |
|---:|---|---|---|
| 0 | `LogFileSize` | $\log_{10}(1 + \text{taille réelle})$ | Discrimine les droppers compacts des installeurs volumineux. |
| 1 | `Is64Bit` | `{0, 1}` | Architecture PE32 vs PE32+ (x64). |
| 2 | `IsDll` | `{0, 1}` | Distinction DLL / exécutable autonome. |
| 3 | `IsSigned` | `{0, 1}` | Présence d'une table de certificats Authenticode (`DataDirectory[4]` / `SigningCertificate`). |
| 4 | `HasDebugInfo` | `{0, 1}` | Présence de métadonnées de débogage (fréquente sur binaires légitimes, souvent retirée sur malwares). |
| 5 | `HasResources` | `{0, 1}` | Présence du répertoire de ressources (icônes, manifestes, versions). |
| 6 | `HasTls` | `{0, 1}` | Présence d'un répertoire TLS (utilisé par certains packers/callbacks anti-analyse). |
| 7 | `HasRelocations` | `{0, 1}` | Présence de la table de relocations (ASLR). |
| 8 | `Subsystem` | `[0..32]` | Sous-système Windows (`2`=GUI, `3`=CUI, `1`=Native, etc.). |
| 9 | `TimestampAnomaly` | `{0, 1}` | Horodatage COFF nul, antérieur à 1995 ou futur (> maintenant + 1 j) ; note : déclenche aussi sur les builds déterministes .NET. |
| 10 | `TimestampYearNorm` | `[-1..2]` | Année de compilation normalisée $(\text{année} - 2000) / 30$, ou `0` si anomalie. |

### 3.2 Sections PE (indices 11–18)

| Indice | Nom | Type / Domaine | Intérêt de détection |
|---:|---|---|---|
| 11 | `SectionCount` | $\ge 0$ | Nombre total de sections PE. |
| 12 | `ExecutableSectionCount` | $\ge 0$ | Nombre de sections marquées `IMAGE_SCN_MEM_EXECUTE` (`0x20000000`). |
| 13 | `WritableExecutableSectionCount` | $\ge 0$ | Nombre de sections simultanément `MEM_WRITE` et `MEM_EXECUTE` (**RWX**, marqueur fort de déchiffrement en mémoire / packer). |
| 14 | `MaxSectionEntropy` | `[0..8]` | Entropie de Shannon maximale parmi les sections (proche de 8 = compression/chiffrement). |
| 15 | `MeanSectionEntropy` | `[0..8]` | Entropie moyenne des sections mesurées. |
| 16 | `MinSectionEntropy` | `[0..8]` | Entropie minimale des sections mesurées. |
| 17 | `VirtualToRawSizeRatio` | `[0..100]` | Ratio $\sum \text{VirtualSize} / \sum \text{SizeOfRawData}$ (élevé lorsque la charge se décompresse en mémoire). |
| 18 | `HasPackerSectionName` | `{0, 1}` | Détection de noms de sections typiques de packers (`UPX0`, `UPX1`, `.aspack`, `.vmp`, `.themida`, `.mpress`, `.enigma`, `FSG`, etc.). |

### 3.3 Imports & Exports (indices 19–26)

| Indice | Nom | Type / Domaine | Intérêt de détection |
|---:|---|---|---|
| 19 | `ImportDllCount` | $\ge 0$ | Nombre de DLL importées distinctes (très faible sur binaires packés). |
| 20 | `ImportFunctionCount` | $\ge 0$ | Nombre de fonctions importées distinctes. |
| 21 | `ExportCount` | $\ge 0$ | Nombre de symboles exportés. |
| 22 | `SuspiciousImportCount` | $\ge 0$ | Total d'API sensibles importées (crypto, réseau, injection, anti-debug, persistance/privilèges). |
| 23 | `CryptoApiCount` | $\ge 0$ | API cryptographiques (`CryptEncrypt`, `BCryptEncrypt`, `CryptGenKey`, etc.). |
| 24 | `NetworkApiCount` | $\ge 0$ | API réseau (`WinHttp*`, `InternetOpen*`, `URLDownloadToFile*`, `WSAStartup`, `connect`, etc.). |
| 25 | `InjectionApiCount` | $\ge 0$ | API d'injection de processus (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`, etc.). |
| 26 | `AntiDebugApiCount` | $\ge 0$ | API anti-débogage / anti-analyse (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `NtSetInformationThread`, etc.). |

### 3.4 Histogramme d'octets résumé & statistiques globales (indices 27–45)

| Indices | Noms | Type / Domaine | Intérêt de détection |
|---:|---|---|---|
| 27–42 | `ByteHistBin00` .. `ByteHistBin15` | `[0..1]` ($\sum = 1$) | Distribution normalisée des octets regroupés en 16 classes de 16 valeurs (`0x00..0x0F` à `0xF0..0xFF`). Un binaire chiffré présente une distribution quasi uniforme ($\approx 0{,}0625$ par bin). |
| 43 | `GlobalByteEntropy` | `[0..8]` | Entropie de Shannon globale sur les 256 valeurs d'octets. |
| 44 | `NullByteRatio` | `[0..1]` | Proportion d'octets `0x00` (élevée dans les binaires non packés/alignés, faible dans les charges chiffrées). |
| 45 | `PrintableAsciiRatio` | `[0..1]` | Proportion d'octets ASCII imprimables (`0x20..0x7E`, `\t`, `\r`, `\n`). |

### 3.5 Statistiques de chaînes — métadonnées uniquement (indices 46–50)

> **Invariant de confidentialité** : Seuls les compteurs agrégés ci-dessous sont calculés sur les séquences ASCII et UTF-16LE de longueur $\ge 5$. Aucune chaîne extraite n'est stockée dans `PeFeatureVector`, les métadonnées ou les journaux.

| Indice | Nom | Type / Domaine | Intérêt de détection |
|---:|---|---|---|
| 46 | `PrintableStringCount` | $\ge 0$ | Nombre de séquences imprimables détectées (souvent réduit sur binaires packés). |
| 47 | `AvgStringLength` | $\ge 0$ | Longueur moyenne des séquences imprimables. |
| 48 | `UrlLikeStringCount` | $\ge 0$ | Nombre de séquences contenant un schéma URL (`http://`, `https://`, `ftp://`, `ws://`, `wss://`). |
| 49 | `PathLikeStringCount` | $\ge 0$ | Nombre de séquences évoquant un chemin Windows (`:\`, `\Windows\`, `\System32\`, `%APPDATA%`, `.exe`, `.ps1`, etc.). |
| 50 | `RegistryStringCount` | $\ge 0$ | Nombre de séquences évoquant une ruche/clé de registre (`HKEY_`, `HKLM\`, `HKCU\`, `CurrentVersion\Run`, `CurrentControlSet`, etc.). |

---

## 4. Protocole d'entraînement, de calibration et d'explicabilité

### 4.1 Algorithme et hyperparamètres par défaut

- **Modèle** : **ML.NET `FastTreeBinaryTrainer`** (Gradient Boosted Decision Trees — MART) suivi d'une **calibration de Platt** (conversion du score brut log-odds en probabilité dans $[0, 1]$).
- **Hyperparamètres par défaut** : `NumberOfTrees = 120`, `NumberOfLeaves = 31`, `MinimumExampleCountPerLeaf = 10`, `LearningRate = 0.1`, `Seed = 42`.
- **Séparation des données** : Découpage **stratifié 80 % entraînement / 20 % évaluation** (`SyntheticPeDatasetGenerator.StratifiedSplit`) préservant strictement la proportion bénin/malveillant et reproductible par graine fixe.

### 4.2 Métriques et calibration à 0,1 % FPR

En sécurité endpoint, l'exactitude globale (*accuracy*) est insuffisante car un taux de faux positifs (FPR) même de 1 % génère des centaines d'alertes erronées sur un poste Windows comportant des dizaines de milliers d'exécutables. `PeClassifierTrainer` calcule donc :

1. **ROC-AUC** : aire sous la courbe ROC (indépendante du seuil).
2. **PR-AUC** : aire sous la courbe Précision-Rappel.
3. **Recall @ 0,1 % FPR** (`targetFpr = 0.001`) :
   - Le nombre maximal de faux positifs tolérés sur le jeu de test négatif de taille $N_-$ est $\text{maxFP} = \lfloor 0{,}001 \times N_- \rfloor$.
   - Le seuil est calibré directement sur le **score brut FastTree** (non saturé en `float32`) au point milieu entre le $(\text{maxFP}+1)$-ième bénin le plus élevé et le premier malveillant strictement au-dessus, garantissant mathématiquement $\text{FPR}_{\text{effectif}} \le 0{,}1\,\%$.
   - Le seuil de probabilité calibré correspondant (`CalibratedThreshold`) est enregistré dans `pe-classifier.meta.json`.
4. **F1, Précision, Rappel et Exactitude** : rapportés à la fois au seuil standard `0.5` et au point de fonctionnement calibré `0.1% FPR`.

### 4.3 Explicabilité locale des prédictions

Pour chaque binaire évalué, `PeMlClassifierService` produit **3 à 5 facteurs lisibles** (`Nom=Valeur`, ex. `MaxSectionEntropy=7.82`, `InjectionApiCount=4`, `IsSigned=0`) :

1. **Méthode principale** : `MLContext.Transforms.CalculateFeatureContribution` appliquée au transformateur FastTree calibré rechargé. Pour chaque arbre, ML.NET mesure l'impact de chaque split traversé par l'échantillon (variation de score en prenant la branche opposée). Les caractéristiques sont classées par contribution alignée avec la prédiction (contributions positives pour un score suspect, négatives pour un score bénin).
2. **Méthode de repli déterministe** : si un modèle externe ne supporte pas `CalculateFeatureContribution`, le service calcule les écarts standardisés (z-scores) par rapport aux moyennes et écarts-types (`FeatureMeans`, `FeatureStdDevs`) enregistrés dans `pe-classifier.meta.json`.

---

## 5. Résultats mesurés sur le jeu synthétique de validation

> **Rappel d'honnêteté scientifique** : Le jeu synthétique modélise 5 profils bénins (système signé, assembly .NET, outil dev non signé, installeur compressé haute entropie, utilitaire d'administration/débogage difficile) et 4 profils malveillants-like (trojan packé + injection, rançongiciel-like, stealer/downloader, chargeur furtif à résolution dynamique). Ses scores élevés valident la **chaîne technique** (extraction, entraînement, calibration, persistance `.zip`, explicabilité), **pas** le taux de détection en conditions réelles.

### 5.1 Mesures reproductibles (`seed = 42`, split stratifié 80/20)

| Configuration CLI | Train / Test | ROC-AUC | PR-AUC | Recall @ 0,1 % FPR | FPR effectif | Seuil calibré (prob) | F1 (0,5) | Précision (0,5) | F1 (0,1 % FPR) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `--synthetic --samples 10000 --trees 120 --leaves 31` | 8 000 / 2 000 (`1000 pos / 1000 neg`) | **0,9995** | **0,9995** | **0,9610** (`TP=961, FP=1`) | **0,100 %** | `0,9893` | **0,9876** | **0,9812** | **0,9796** |
| `--synthetic --samples 2500 --trees 80 --leaves 24` | 2 000 / 500 (`250 pos / 250 neg`) | **0,9984** | **0,9984** | **0,8040** (`TP=201, FP=0`) | **0,000 %** | `0,9984` | **0,9841** | **0,9764** | **0,8914** |

### 5.2 Top caractéristiques globales (gain cumulé FastTree, run 10 000 échantillons)

1. `SuspiciousImportCount` (gain normalisé `1.0000`)
2. `VirtualToRawSizeRatio` (`0.2423`)
3. `ImportDllCount` (`0.1733`)
4. `PrintableStringCount` (`0.1427`)
5. `ExecutableSectionCount` (`0.1404`)
6. `WritableExecutableSectionCount` (`0.1154`)
7. `RegistryStringCount` (`0.1060`)
8. `CryptoApiCount` (`0.0972`)

### 5.3 Vérification sur un binaire PE réel (`Sentinel.Shared.dll`)

Commande exécutée (`--inspect src/Sentinel.Shared/bin/Debug/net10.0/Sentinel.Shared.dll`) :
- Caractéristiques extraites : `IsDll=1`, `IsSigned=0`, `HasDebugInfo=1`, `HasResources=1`, `HasRelocations=1`, `SectionCount=3`, `ExecutableSectionCount=1`, `WritableExecutableSectionCount=0`, `MaxSectionEntropy=5.91`, `GlobalByteEntropy=5.89`, `NullByteRatio=0.27`, `PrintableAsciiRatio=0.39`, `PrintableStringCount=3476`, `AvgStringLength=15.36`, `SuspiciousImportCount=0`.
- Inférence avec le modèle rechargé (`2.0.0-synthetic`) :
  - **Probabilité malveillante** : `0.0015`
  - **Contribution plafonnée** : `0 / 35`
  - **Top 5 caractéristiques explicatives (ML.NET FCC)** : `RegistryStringCount=0`, `WritableExecutableSectionCount=0`, `VirtualToRawSizeRatio=1.00`, `AntiDebugApiCount=0`, `ExecutableSectionCount=1`.

---

## 6. Obtention légale et utilisation du dataset EMBER (sans jamais le commiter)

### 6.1 Sources légales recommandées

- **EMBER 2018 v2** (*Elastic / Endgame*) : publié sur GitHub (`https://github.com/elastic/ember`). Le jeu de données ne contient **aucun binaire malveillant exécutable** : il fournit uniquement des caractéristiques statiques JSONL extraites de ~1,1 million de fichiers PE (bénins, malveillants et non étiquetés `label = -1`), ce qui permet un entraînement local sûr et légal sans manipuler de malwares actifs.
- **SOREL-20M** (*Sophos / ReversingLabs*) : alternative académique publique (métadonnées + vecteurs EMBER).

### 6.2 Règle absolue d'hygiène Git

> **Ne commitez JAMAIS** dans le dépôt Git :
> - les archives ou fichiers `.jsonl` / `.csv` EMBER ou SOREL-20M ;
> - aucun binaire malveillant ni échantillon VirusTotal/MalwareBazaar ;
> - les modèles binaires entraînés `pe-classifier.zip` (stockés exclusivement dans `%ProgramData%\Sentinel\models` ou un dossier local hors dépôt).

### 6.3 Commandes d'entraînement local avec `Sentinel.ML.Trainer`

```powershell
# 1) Démonstration / test d'architecture sur jeu synthétique
dotnet run --project src/Sentinel.ML.Trainer -- --synthetic --output "$env:ProgramData\Sentinel\models"

# 2) Entraînement direct sur EMBER 2018 JSONL obtenu légalement (hors dépôt)
dotnet run --project src/Sentinel.ML.Trainer -- `
    --ember-jsonl "D:\Datasets\ember2018\train_features_0.jsonl" `
    --version "2.0.0-ember2018" `
    --trees 200 --leaves 63 --learning-rate 0.08 `
    --output "$env:ProgramData\Sentinel\models"

# 3) Entraînement sur un CSV pré-converti par l'utilisateur
dotnet run --project src/Sentinel.ML.Trainer -- `
    --csv "D:\Datasets\ember_51features.csv" `
    --version "2.0.0-custom-csv" `
    --output "$env:ProgramData\Sentinel\models"

# 4) Inspection des 51 caractéristiques et inférence sur un binaire PE local
dotnet run --project src/Sentinel.ML.Trainer -- `
    --inspect "C:\Windows\System32\notepad.exe" `
    --output "$env:ProgramData\Sentinel\models"
```

---

## 7. Limites connues et surface d'évasion

Un classifieur statique de fichiers PE souffre de limites structurelles bien documentées dans la littérature sécurité. SENTINEL les assume explicitement et les compense par l'architecture multi-moteurs :

### 7.1 Dérive de concept (*concept drift*)
- Les binaires Windows évoluent rapidement : adoption de **Rust**, **Go**, **.NET NativeAOT**, builds déterministes (horodatages PE non chronologiques produisant `TimestampAnomaly=1` sur des binaires légitimes récents, comme observé ci-dessus sur `Sentinel.Shared.dll`), nouveaux packers commerciaux et nouvelles familles malveillantes.
- Un modèle entraîné sur EMBER 2018 voit son Recall @ 0,1 % FPR se dégrader significativement sur des malwares compilés en 2025–2026.
- **Mitigation** : versionnage explicite dans `pe-classifier.meta.json` (`Version`, `TrainedAt`, `DatasetNotice`), rechargement à chaud (`Reload()`), et ré-entraînement périodique sur des corpus actualisés.

### 7.2 Évasion adversariale
- **Padding / overlay bénin** : l'ajout de quelques mégaoctets d'octets nuls ou de chaînes anglaises en fin de fichier (overlay) fait chuter `GlobalByteEntropy`, remonte `NullByteRatio` et `PrintableStringCount`, et fausse l'histogramme d'octets (d'où la lecture bornée et l'analyse d'entropie par section, qui atténue sans éliminer totalement le risque).
- **Signature Authenticode volée ou auto-signée** : `PeFeatureExtractor` vérifie la présence statique de la table de signature (`IsSigned`) sans validation OCSP/chaîne de confiance réseau, afin de rester rapide et hors-ligne. Un binaire signé avec un certificat compromis ou auto-signé obtient `IsSigned=1`. La vérification complète de chaîne de confiance reste assurée par Windows/Defender et l'analyse statique dédiée.
- **Résolution dynamique d'API & syscalls directs** : un malware utilisant *API hashing* (`GetProcAddress`, parcours PEB) ou des syscalls directs n'expose presque aucun import suspect (`InjectionApiCount=0`, `SuspiciousImportCount` faible).
- **Attaques *Living-off-the-Land* (LOLBins) & scripts** : `powershell.exe`, `mshta.exe`, `certutil.exe` ou `rundll32.exe` sont des binaires Microsoft signés et parfaitement bénins statiquement. Le ML PE ne peut par définition pas les détecter : c'est le rôle de la visibilité PowerShell 4104/AMSI (M7), des règles Sigma (M2) et de la corrélation comportementale (M8).

### 7.3 Biais de dataset
- **Biais sur les binaires bénins** : les jeux publics sous-représentent souvent les logiciels métiers internes, les outils open-source non signés, les compilateurs/débogueurs et les installeurs compressés (NSIS, Inno Setup, PyInstaller), qui partagent plusieurs traits statistiques avec les malwares packés (haute entropie, `IsSigned=0`).
- **Biais du jeu synthétique** : les distributions gaussiennes/archétypales de `SyntheticPeDatasetGenerator` restent beaucoup plus régulières que des PE sauvages réels ; le modèle `2.0.0-synthetic` ne doit jamais être considéré comme une protection réelle contre les malwares.

### 7.4 Limites de l'explicabilité
- Les facteurs retournés par `CalculateFeatureContribution` expliquent **pourquoi le modèle FastTree a augmenté ou diminué son score**, et non une preuve causale d'activité malveillante. Un analyste doit toujours croiser ces indicateurs avec les détections YARA, Sigma, Threat Intel et les événements comportementaux du cluster.
