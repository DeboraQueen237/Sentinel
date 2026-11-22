# SENTINEL — Agent de détection et de prévention des menaces avec moteur de corrélation

> Documentation de conception v0.1 — Projet académique/professionnel, 100 % C# (.NET 8)

---

## 1. Présentation

**SENTINEL** est un système de sécurité composé de :

1. **Un agent** exécuté en continu sur le poste (service Windows) qui collecte des événements techniques.
2. **Un cœur d'analyse** qui attribue à chaque événement un score de menace contextuel (IA locale + règles), puis recherche des corrélations entre événements.
3. **Un moteur de réponse** qui applique des actions graduées selon le niveau de menace.
4. **Une console d'administration** (dashboard + graphe de corrélation) pour un administrateur unique (responsable sécurité ou RH).

### 1.1 Objectif central

Détecter les **signaux faibles** et les **patterns émergents** avant qu'une campagne (phishing, ingénierie sociale, intrusion) n'atteigne l'ensemble du système. Dès qu'un second événement similaire est observé dans un même contexte, le niveau de menace est relevé automatiquement et les défenses sont déclenchées, sans attendre la compromission.

### 1.2 Ce que le projet démontre scientifiquement

Il s'agit d'une **prévention mesurable**, pas d'une prédiction générale. L'hypothèse testable est :

> *La corrélation d'événements individuellement faibles réduit le délai de détection d'une chaîne d'attaque (Time-To-Detect) par rapport à une analyse événement par événement, à taux de faux positifs comparable.*

---

## 2. Périmètre, éthique et cadre légal

### 2.1 Données collectées (liste fermée)

| Canal | Données collectées | Données exclues |
|---|---|---|
| Processus | Lancement, arrêt, chemin, hash, parent, signature, nouvelles installations | Contenu mémoire |
| Réseau | Connexions actives, IP/port/domaine, volumes | Contenu des paquets |
| Presse-papiers | Détection d'URL ou de motifs à risque avant collage | Stockage du contenu brut (seuls hash + type + domaine sont conservés) |
| Fichiers | Création/modification dans les dossiers surveillés (chemin, extension, taille, entropie) | Lecture du contenu des documents |
| Sessions | Ouverture, fermeture, verrouillage, échecs d'authentification | Mots de passe |
| Périphériques | Branchement USB, nouveaux périphériques (VID/PID, classe) | Contenu des supports |
| Navigation | Domaine/URL visités et cliqués, via extension navigateur dédiée | Contenu des pages, formulaires, mots de passe |
| Dynamique de saisie | **Uniquement** statistiques de rythme (vitesse, régularité) pour détecter l'automatisation ou un usage anormal | **Jamais les touches frappées** |

### 2.2 Exclusions explicites

- Contenu des messageries chiffrées (WhatsApp, Signal, etc.) : **exclu**.
- **Aucun enregistrement du texte saisi** (pas de keylogger). Un keylogger est une technique de logiciel malveillant, expose des mots de passe et données bancaires, et est juridiquement risqué. La détection d'anomalie de saisie se fait sur les temps inter-touches uniquement (voir §6.6).

### 2.3 Consentement et transparence

- Écran de consentement explicite à l'installation, listant les canaux ci-dessus.
- Icône visible dans la zone de notification indiquant que l'agent est actif.
- Journal d'accès consultable : toute consultation d'une fiche par l'administrateur est elle-même journalisée.
- Politique de rétention : 90 jours par défaut pour les événements bruts, 12 mois pour les alertes.
- Minimisation et chiffrement des données au repos.

### 2.4 Cadre légal

Vérifier avant tout déploiement sur le poste d'autres personnes : droit local de protection des données (au Cameroun, la loi sur la cybersécurité et la cybercriminalité de 2010 et ses textes d'application ; le RGPD si des données de résidents UE sont concernées), information des employés, et rôle de l'administrateur RH (séparation entre supervision de sécurité et surveillance de performance). En cas de doute, faire valider par un juriste.

---

## 3. Exigences

### 3.1 Fonctionnelles

| ID | Exigence |
|---|---|
| F1 | L'agent collecte les événements en continu, démarre avec Windows et survit à la fermeture de session. |
| F2 | Chaque événement est normalisé dans un schéma commun. |
| F3 | Chaque événement reçoit un score 0–100 avec justification textuelle. |
| F4 | Le moteur de corrélation relie les événements partageant un contexte commun. |
| F5 | Le score d'un groupe corrélé est recalculé et peut dépasser le score de chaque événement. |
| F6 | Les actions de réponse sont déterminées par la matrice score/type (§9). |
| F7 | Le blocage automatique est réversible en un clic. |
| F8 | Le dashboard affiche score global, alertes, blocages, fiches, rapports. |
| F9 | Le graphe de corrélation est explorable (zoom, filtre, clic sur nœud). |
| F10 | Export des rapports (PDF/JSON) avec justification de chaque décision. |

### 3.2 Non fonctionnelles

- **Performance** : agent < 3 % CPU et < 150 Mo RAM en moyenne.
- **Disponibilité** : redémarrage automatique du service, file d'attente locale si le cœur est indisponible.
- **Confidentialité** : IA 100 % locale, aucune donnée envoyée sur Internet.
- **Intégrité** : journaux signés (chaîne de hash) pour détecter toute altération.
- **Auto-protection** : l'agent détecte sa propre désactivation ou modification.
- **Explicabilité** : toute décision doit être justifiable (score, règle, contexte).

---

## 4. Architecture

```
┌──────────────────────── POSTE SURVEILLÉ ────────────────────────┐
│                                                                  │
│  Sentinel.Agent (Windows Service, .NET Worker)                  │
│   ├─ Collecteurs : Process, Network, Clipboard, FileSystem,     │
│   │                Session, USB, Browser, TypingRhythm          │
│   ├─ Normalisation + file locale (SQLite / Channel<T>)          │
│   └─ Exécuteur d'actions (blocage, quarantaine, isolation)      │
│                │  gRPC / Named Pipe (mTLS)                      │
│                ▼                                                 │
│  Sentinel.Core (service d'analyse)                              │
│   ├─ Ingestion API                                              │
│   ├─ Scoring (règles + IA via Ollama)                           │
│   ├─ Moteur de corrélation (fenêtres glissantes + graphe)       │
│   ├─ Moteur de décision (matrice score → action)                │
│   ├─ Stockage (SQLite → PostgreSQL)                             │
│   └─ API REST + SignalR (temps réel)                            │
│                │                                                 │
│                ▼                                                 │
│  Sentinel.Admin (dashboard) ◄── Ollama (localhost:11434)        │
└──────────────────────────────────────────────────────────────────┘
```

### 4.1 Choix technologiques

| Couche | Technologie | Justification |
|---|---|---|
| Plateforme | .NET 8 (LTS) | Moderne, performant, services Windows natifs |
| Agent | `Microsoft.Extensions.Hosting.WindowsServices` | Service Windows géré proprement |
| Collecte bas niveau | `Microsoft.Diagnostics.Tracing.TraceEvent` (ETW), WMI (`System.Management`), `System.Diagnostics.Eventing.Reader` | Événements système fiables |
| Communication | gRPC (`Grpc.AspNetCore`) | Typé, rapide, mTLS |
| Stockage | SQLite (MVP) puis PostgreSQL, via EF Core | Simplicité d'abord |
| IA locale | Ollama via HTTP (`OllamaSharp`) | Déjà installé |
| Dashboard | **Blazor Server** + SignalR | 100 % C#, temps réel |
| Graphe | Cytoscape.js via JS interop (ou `MudBlazor` + composant graphe) | Visualisation interactive explorable |
| Journalisation | Serilog | Structuré |
| Tests | xUnit, FluentAssertions, Testcontainers | Qualité |

> Remarque : Blazor utilise un peu de JavaScript pour le rendu du graphe, tout le reste est en C#. Une alternative 100 % C# existe (WPF + `MSAGL`/`GraphSharp`) mais l'exploration visuelle y est moins fluide.

---

## 5. Modèle de données

### 5.1 Événement normalisé

```csharp
public record SecurityEvent(
    Guid Id,
    DateTimeOffset Timestamp,
    string HostId,
    string UserId,
    EventCategory Category,      // Process, Network, Clipboard, File, Session, Device, Browser, Typing
    string EventType,            // ex: "ProcessStart", "UrlOpened", "UsbInserted"
    string Subject,              // entité principale (chemin, domaine, device id...)
    IReadOnlyDictionary<string,string> Attributes,
    string? CorrelationHints);   // domaine, hash, parent PID, etc.
```

### 5.2 Résultat de scoring

```csharp
public record ThreatAssessment(
    Guid EventId,
    int Score,                   // 0..100
    ThreatType Type,             // Phishing, Malware, Intrusion, Exfiltration, SocialEngineering, Anomaly...
    string Justification,
    string Source,               // "Rules" | "LLM" | "Hybrid"
    double Confidence);
```

### 5.3 Entités du graphe

Nœuds : `Event`, `Process`, `File`, `Domain`, `IP`, `User`, `Device`, `Threat`.
Arêtes : `SPAWNED`, `CONNECTED_TO`, `WROTE`, `COPIED_FROM_CLIPBOARD`, `OPENED_URL`, `SAME_DOMAIN`, `SAME_WINDOW`, `SAME_ANOMALY_TYPE`.

---

## 6. Collecteurs (Agent)

| # | Collecteur | Mécanisme .NET | Événements produits |
|---|---|---|---|
| 6.1 | Processus | ETW `Microsoft-Windows-Kernel-Process` / WMI `Win32_ProcessStartTrace` | Lancement, parent, ligne de commande, hash SHA-256, signature Authenticode |
| 6.2 | Réseau | ETW `Microsoft-Windows-TCPIP` / `IPGlobalProperties` | Connexions, IP/port, volume émis/reçu, domaine résolu (DNS-Client ETW) |
| 6.3 | Presse-papiers | `AddClipboardFormatListener` (P/Invoke) | Détection d'URL, raccourcisseur de lien, domaine suspect, motif de commande PowerShell copiée. **Seul le type + domaine + hash sont conservés.** |
| 6.4 | Fichiers | `FileSystemWatcher` sur dossiers configurés (Téléchargements, Bureau, Documents, Temp) | Création/modif/renommage, extension, taille, entropie, double extension (`facture.pdf.exe`), rafale de chiffrement (ransomware) |
| 6.5 | Sessions | Journal Sécurité (4624, 4625, 4634, 4647, 4800/4801) | Connexion, échec, déconnexion, verrouillage, horaires inhabituels |
| 6.6 | Dynamique de saisie | Hook bas niveau **limité aux horodatages** (aucun code touche enregistré) | Vitesse moyenne, variance inter-touches. Détecte la saisie scriptée/injectée (ex. clé USB « BadUSB ») |
| 6.7 | Périphériques | WMI `Win32_DeviceChangeEvent` / `Win32_PnPEntity` | USB inséré, classe (HID, stockage), VID/PID, nouveau clavier suspect |
| 6.8 | Navigation | Extension navigateur (Chrome/Edge, Manifest V3) + Native Messaging vers l'agent C# | URL visitée, clic sur lien externe, âge du domaine, redirections |
| 6.9 | Installations | Registre `Uninstall`, MSI events | Nouvelle application, éditeur, signature |

### 6.10 Détection du lien suspect cliqué sans vérification

Séquence typique repérée : `Clipboard(URL raccourcie)` → `Browser(ouverture)` → `File(téléchargement exécutable)` → `Process(lancement)` → `Network(IP inconnue)`. Aucun maillon n'est grave seul ; l'enchaînement est le signal.

---

## 7. Scoring IA contextuel

### 7.1 Principe hybride (recommandé)

1. **Pré-filtre déterministe** (rapide, gratuit) : liste blanche (processus signés connus, domaines habituels), enrichissement (réputation locale, entropie, ancienneté).
2. **Baseline comportementale** : profil des habitudes de l'utilisateur (heures, applications, domaines fréquents) pour mesurer l'écart.
3. **LLM local (Ollama)** pour les événements non triviaux : évalue la gravité en contexte et justifie.
4. **Garde-fous** : sortie JSON validée par schéma ; si échec/timeout → score de repli par règles.

> L'IA n'est appelée que sur les événements ambigus (~5 à 10 %). Appeler un LLM sur chaque événement saturerait le poste.

### 7.2 Modèles recommandés (Ollama)

| Usage | Modèle conseillé | RAM approx. |
|---|---|---|
| Machine modeste (8 Go) | `qwen2.5:3b` ou `phi3:mini` | 3–4 Go |
| Machine standard (16 Go) | `qwen2.5:7b` ou `llama3.1:8b` | 6–8 Go |
| Embeddings (similarité d'événements) | `nomic-embed-text` | < 1 Go |

Paramètres : `temperature = 0`, `format = "json"`, contexte court, timeout 10 s.

### 7.3 Prompt de scoring (squelette)

```
Tu es un analyste SOC. Évalue l'événement ci-dessous dans son contexte.
Contexte récent (30 min) : {liste d'événements résumés}
Profil habituel de l'utilisateur : {résumé baseline}
Événement : {json}
Réponds UNIQUEMENT en JSON :
{"score": 0-100, "type": "...", "justification": "...", "confidence": 0-1}
```

### 7.4 Sécurité du LLM

Les données collectées (noms de fichiers, URLs, texte copié) sont **non fiables** et peuvent contenir des instructions malveillantes (prompt injection). Règles : encadrer les données dans des balises, ne jamais laisser le LLM déclencher une action directement, la décision passe toujours par le moteur de décision déterministe.

---

## 8. Moteur de corrélation (cœur du projet)

### 8.1 Clés de contexte

Deux événements sont candidats à une corrélation s'ils partagent au moins une clé :

- **Entité** : même domaine, même hash, même processus parent, même fichier.
- **Temps** : même fenêtre glissante (5 min, 30 min, 24 h).
- **Anomalie** : même type de menace.
- **Service/poste** : même HostId ou groupe.

### 8.2 Algorithme

1. Chaque événement noté est inséré dans l'index mémoire par clé de contexte.
2. On récupère les événements voisins dans les fenêtres configurées.
3. On crée/met à jour un **cluster** (composante connexe du graphe).
4. Le score du cluster est recalculé :

```
ScoreCluster = min(100, max(score_i) + Σ (score_j × poids_lien × facteur_temps) + bonus_séquence)
```

- `poids_lien` : 0,3 (même type) à 0,8 (même entité).
- `facteur_temps` : décroissance exponentielle selon l'écart.
- `bonus_séquence` : +15 à +30 si le cluster correspond à une chaîne d'attaque connue (§8.3).

5. **Règle d'escalade précoce** : dès le **2ᵉ événement similaire** dans un même contexte, le niveau est relevé d'un cran et l'administrateur est alerté.

### 8.3 Chaînes d'attaque modélisées (MVP)

| Pattern | Séquence |
|---|---|
| Phishing → exécution | Presse-papiers/lien → navigation → téléchargement → exécution → connexion sortante |
| BadUSB | USB HID inséré → saisie ultra-rapide → lancement PowerShell/cmd |
| Ransomware | Rafale de modifications + hausse d'entropie + extensions modifiées |
| Exfiltration | Gros volume sortant + archive créée + domaine rare |
| Brute force / intrusion | N échecs de connexion → succès → processus inhabituel |
| Persistance | Nouvelle installation + clé de démarrage + tâche planifiée |
| Ingénierie sociale | Lien raccourci + domaine récent + exécutable téléchargé aussitôt |

### 8.4 Mesure de la prévention

Pour chaque scénario : mesurer **le moment où l'alerte corrélée se déclenche** versus **le moment où une analyse événement-par-événement l'aurait fait**. Ce gain (en événements et en secondes) est la métrique centrale du mémoire.

---

## 9. Décision graduée et actions

### 9.1 Niveaux

| Niveau | Score | Nom | Mode de décision |
|---|---|---|---|
| 0 | 0–29 | Info | Journalisation seule |
| 1 | 30–54 | Faible | Journalisation + marquage pour corrélation |
| 2 | 55–74 | Modéré | Notification discrète à l'utilisateur + surveillance renforcée |
| 3 | 75–89 | Élevé | **Alerte administrateur, décision humaine** |
| 4 | 90–100 | Critique | **Blocage automatique réversible** + alerte immédiate |

Seuils configurables.

### 9.2 Matrice d'actions par type de menace

| Type de menace | Niv. 1–2 | Niv. 3 (élevé) | Niv. 4 (critique) |
|---|---|---|---|
| Phishing / lien suspect | Log, avertissement | Alerte admin, bloquer le domaine (proposition) | Bloquer domaine (hosts/pare-feu), fermer l'onglet via extension |
| Exécutable malveillant | Log, hash en liste de surveillance | Alerte admin, suspension du processus | Kill du processus, quarantaine du fichier (réversible) |
| Ransomware | Surveillance | Alerte + suspension du processus | Kill + isolement réseau + protection des dossiers |
| BadUSB / périphérique | Log | Alerte + désactivation du périphérique proposée | Désactivation du périphérique (PnP disable) |
| Exfiltration | Log | Alerte + limitation du trafic | Coupure de la connexion sortante du processus (règle pare-feu) |
| Intrusion / brute force | Log | Alerte + verrouillage de session proposé | Verrouillage du compte, blocage IP source |
| Ingénierie sociale | Sensibilisation (message à l'utilisateur) | Alerte admin + rapport | Blocage des domaines liés, escalade |
| Anomalie comportementale | Log | Alerte + revue humaine | Verrouillage de session |

### 9.3 Réversibilité

Chaque action produit un **ticket d'action** stockant l'état initial (règle pare-feu ajoutée, fichier déplacé vers `%ProgramData%\Sentinel\Quarantine` chiffré, périphérique désactivé) pour permettre le **« Annuler »** depuis le dashboard. Les actions destructives (suppression définitive) sont interdites en automatique.

### 9.4 Anti-faux-positifs

- Liste d'exclusions (processus système, outils de l'utilisateur).
- Période de **mode apprentissage** (7 jours, aucune action automatique) pour construire la baseline.
- Mode « simulation » : l'action est journalisée mais non exécutée.
- Retour de l'administrateur (« faux positif ») réinjecté dans la baseline.

---

## 10. Console d'administration

### 10.1 Écrans

1. **Vue d'ensemble** : score de sécurité global, alertes actives, blocages en cours, courbe des menaces sur 24 h/7 j.
2. **Alertes** : liste filtrable, détail avec justification IA, événements liés, boutons *Approuver / Rejeter / Annuler le blocage*.
3. **Graphe de corrélation** : nœuds colorés par type et par score, clic pour détails, filtre temporel, mise en évidence des clusters.
4. **Fiches** : fiche par poste/compte/entité avec historique et baseline.
5. **Actions & blocages** : comptes, périphériques, domaines bloqués, annulation.
6. **Rapports** : export PDF/JSON, justification de chaque décision.
7. **Paramètres** : seuils, dossiers surveillés, exclusions, rétention, modèle Ollama, mode simulation/apprentissage.
8. **Audit** : journal des accès de l'administrateur.

### 10.2 Authentification

Compte administrateur unique, mot de passe haché (Argon2/PBKDF2) + 2FA TOTP, session courte, journalisation de chaque action.

---

## 11. Auto-protection et sécurité du système

- Service lancé sous `LocalSystem`, binaires signés.
- Communication agent ↔ cœur chiffrée (mTLS) avec certificats générés à l'installation.
- Chaîne de hash des journaux (chaque entrée contient le hash de la précédente).
- *Watchdog* : un second processus relance l'agent, alerte si le service est arrêté/modifié.
- Contrôle d'intégrité des binaires au démarrage.
- Secrets stockés via DPAPI.
- Principe du moindre privilège : le dashboard n'a aucun droit d'exécution direct, il passe par l'API.

---

## 12. Structure du dépôt

```
Sentinel/
├── README.md
├── LICENSE
├── .gitignore
├── .editorconfig
├── Directory.Build.props
├── Sentinel.sln
├── docs/
│   ├── architecture.md
│   ├── privacy-and-consent.md
│   ├── threat-model.md
│   ├── correlation-rules.md
│   ├── decision-matrix.md
│   └── test-plan.md
├── src/
│   ├── Sentinel.Shared/          # modèles, enums, contrats gRPC
│   ├── Sentinel.Agent/           # service Windows + collecteurs
│   ├── Sentinel.Core/            # ingestion, scoring, corrélation, décision
│   ├── Sentinel.AI/              # client Ollama, prompts, validation JSON
│   ├── Sentinel.Storage/         # EF Core, migrations
│   ├── Sentinel.Admin/           # Blazor Server (dashboard + graphe)
│   └── Sentinel.Installer/       # WiX / MSIX + écran de consentement
├── tests/
│   ├── Sentinel.Core.Tests/
│   ├── Sentinel.Agent.Tests/
│   └── Sentinel.Simulation/      # scénarios d'attaque simulés
└── .github/workflows/ci.yml
```

---

## 13. Feuille de route

| Phase | Durée indicative | Livrables |
|---|---|---|
| **0. Préparation** | 1 sem. | Dépôt, solution, CI, modèle de menace, validation éthique |
| **1. Socle** | 2 sem. | Modèle d'événement, agent service, stockage, canal gRPC |
| **2. Collecteurs** | 3 sem. | Processus, fichiers, sessions, USB, réseau, presse-papiers |
| **3. Scoring** | 2 sem. | Règles + baseline + intégration Ollama + fallback |
| **4. Corrélation** | 3 sem. | Index de contexte, clusters, scoring de cluster, chaînes d'attaque |
| **5. Décision & réponse** | 2 sem. | Matrice d'actions, quarantaine, blocage réversible |
| **6. Dashboard** | 3 sem. | Vue globale, alertes, graphe, rapports |
| **7. Navigation & saisie** | 2 sem. | Extension navigateur, rythme de frappe |
| **8. Évaluation** | 2 sem. | Scénarios, métriques, rapport de résultats |
| **9. Durcissement** | 1–2 sem. | Auto-protection, installeur, documentation finale |

**MVP recommandé (phases 0–5 + dashboard minimal) :** processus + fichiers + USB + réseau, scoring hybride, corrélation, 3 chaînes d'attaque, décision graduée.

---

## 14. Plan de test et évaluation

### 14.1 Scénarios de simulation (environnement isolé : machine virtuelle)

| Scénario | Outil de simulation |
|---|---|
| Fichier de test antivirus | Fichier **EICAR** (inoffensif) |
| Techniques d'attaque | **Atomic Red Team** (tests MITRE ATT&CK, sûrs et documentés) |
| Ransomware simulé | Script maison qui renomme/chiffre des fichiers factices dans un dossier test |
| Phishing | Page locale + lien raccourci vers un exécutable inoffensif |
| BadUSB | Raspberry Pi Pico / Digispark programmé pour saisir une commande bénigne |
| Brute force | Tentatives de connexion échouées scriptées |

> Réalisez les tests uniquement dans une **VM dédiée** avec instantanés (snapshots).

### 14.2 Métriques

- **Taux de détection** (rappel), **précision**, **taux de faux positifs** / jour.
- **Time-To-Detect** : corrélation vs analyse individuelle (métrique clé).
- Nombre d'événements avant alerte (le « 2ᵉ événement » est-il bien suffisant ?).
- Latence du scoring IA, consommation CPU/RAM.
- Taux de succès de la réversibilité des actions.

### 14.3 Comparaison de référence

Comparer trois configurations : (A) règles seules, (B) règles + IA sans corrélation, (C) règles + IA + corrélation. Le résultat attendu est un meilleur Time-To-Detect pour (C).

### 14.4 Cadre de référence

Mapper chaque détection à **MITRE ATT&CK** (ex. T1566 Phishing, T1204 User Execution, T1059 PowerShell, T1486 Chiffrement de données, T1052 Exfiltration via support physique) pour une démonstration crédible.

---

## 15. Prérequis avant de démarrer

### 15.1 Environnement

- [ ] Windows 10/11 (64 bits) de développement
- [ ] **Visual Studio 2022** (charges : *Développement .NET desktop*, *ASP.NET et web*) ou VS Code + C# Dev Kit
- [ ] **.NET 8 SDK**
- [ ] **Git** + compte GitHub/GitLab
- [ ] **Ollama** fonctionnel : `ollama pull qwen2.5:7b` puis test sur `http://localhost:11434`
- [ ] **Machine virtuelle** de test (Hyper-V, VirtualBox ou VMware) avec snapshots, *obligatoire* pour les simulations d'attaque
- [ ] Droits administrateur local pour développer le service
- [ ] Windows Sandbox activé (tests rapides)

### 15.2 Compétences à consolider

`BackgroundService`/Worker Services, ETW avec TraceEvent, WMI, gRPC, EF Core, Blazor Server + SignalR, P/Invoke, Authenticode/signature, MITRE ATT&CK.

### 15.3 Préparation Git

```bash
git init Sentinel && cd Sentinel
dotnet new sln -n Sentinel
dotnet new gitignore
git add . && git commit -m "chore: initial commit"
git branch -M main
git remote add origin <URL_DU_DEPOT>
git push -u origin main
```

Bonnes pratiques :
- Branches : `main` (stable), `develop`, `feature/<nom>`.
- Commits suivant *Conventional Commits* (`feat:`, `fix:`, `docs:`, `test:`).
- **Ne jamais commiter** : certificats, clés, mots de passe, bases de données, journaux contenant des données réelles (`.gitignore`).
- Licence : MIT/Apache 2.0 si ouvert ; sinon dépôt **privé** (conseillé tant que le code contient des mécanismes de blocage).
- CI GitHub Actions : `dotnet build` + `dotnet test` à chaque push.
- Issues et *Milestones* correspondant aux phases du §13.

### 15.4 Documents à rédiger en premier

1. `privacy-and-consent.md` : texte de consentement.
2. `threat-model.md` : menaces visées et hors périmètre (STRIDE).
3. `decision-matrix.md` : seuils et actions (reprendre §9).
4. `test-plan.md` : scénarios et métriques (reprendre §14).

---

## 16. Risques et limites

| Risque | Mitigation |
|---|---|
| Faux positifs bloquant l'utilisateur | Mode apprentissage, simulation, actions réversibles, retour admin |
| Surcharge CPU/RAM (LLM) | Appel LLM sélectif, petit modèle, file d'attente, timeout |
| Contournement par un malware privilégié | Auto-protection, watchdog, limite assumée (un agent en espace utilisateur/service n'égale pas un pilote noyau) |
| Prompt injection via données collectées | Isolation des données, sortie JSON validée, décision déterministe |
| Dérive éthique (surveillance excessive) | Liste fermée de canaux, aucun contenu, audit des accès, consentement |
| Complexité de l'extension navigateur | Prévoir en phase 7, MVP sans navigation si besoin |
| Hallucination du LLM | Score de repli par règles, confiance minimale, jamais d'action directe |

### Limites assumées du projet

SENTINEL est un **agent de détection et de réponse (EDR léger)**. Il ne remplace pas un antivirus à pilote noyau (Microsoft Defender) : il doit **le compléter**. Conservez Defender actif.

---

## 17. Glossaire

- **ETW** : Event Tracing for Windows, flux d'événements du noyau.
- **EDR** : Endpoint Detection and Response.
- **SOC** : Security Operations Center.
- **Signal faible** : événement peu grave isolément, significatif en groupe.
- **Cluster** : ensemble d'événements corrélés.
- **TTD** : Time-To-Detect, délai de détection.
- **IOC** : Indicator of Compromise.

---

*Fin du document — v0.1. À versionner dans `docs/` du dépôt et à faire évoluer à chaque phase.*
