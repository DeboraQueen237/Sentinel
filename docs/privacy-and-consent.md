# Vie privée, éthique, consentement et cadre légal

> Document de gouvernance et de conformité de **SENTINEL** (cohérent avec la section §2 de `SENTINEL_Documentation.md` et l'implémentation effective des collecteurs).

---

## 1. Principes fondateurs

SENTINEL est conçu selon le principe de **protection de la vie privée dès la conception (*Privacy by Design*)** et de **minimisation stricte des données** :

1. **Finalité unique de cybersécurité** : SENTINEL détecte des menaces techniques (phishing, malware, ransomware, BadUSB, exfiltration, intrusion, persistance). Il n'est **jamais** destiné à mesurer la productivité, le temps de travail ou l'activité rédactionnelle d'un employé.
2. **Traitement 100 % local** : l'analyse par règles, la baseline comportementale, la corrélation et le modèle de langage (Ollama) s'exécutent localement. Aucune donnée collectée n'est envoyée vers Internet ou vers un service IA tiers.
3. **Liste fermée de canaux** : seules des métadonnées techniques strictement nécessaires à la détection sont collectées ; le contenu des communications, documents et frappes clavier est **exclu par architecture**.
4. **Transparence active** : l'utilisateur est informé avant l'installation (consentement explicite), voit en permanence l'icône de l'agent actif (`Sentinel.Tray`) et bénéficie de la traçabilité des consultations de l'administrateur.

---

## 2. Périmètre des données collectées (liste fermée)

Chaque événement produit par l'agent appartient à l'une des catégories de `EventCategory` (`src/Sentinel.Shared/Models/Enums.cs`) et ne porte que des attributs normalisés de `AttributeKeys` (`EventTypes.cs`).

| # | Canal (`EventCategory`) | Collecteur / Mécanisme | Métadonnées collectées | Données strictement exclues |
|---|---|---|---|---|
| 1 | `Process` | ETW `Microsoft-Windows-Kernel-Process` / WMI | Nom, chemin, PID, parent PID/nom, ligne de commande, hash SHA-256, signature Authenticode, éditeur, élévation | Contenu mémoire RAM, variables d'environnement secrètes |
| 2 | `Network` | ETW TCPIP / DNS-Client / `IPGlobalProperties` | IP/port locaux et distants, protocole, direction, volume d'octets émis/reçus, domaine DNS résolu | **Contenu des paquets (payload)**, corps HTTP/TLS |
| 3 | `Clipboard` | `AddClipboardFormatListener` (`Sentinel.Tray`) | Type de motif détecté (`url`, `command`), domaine extrait, indicateur raccourcisseur, **empreinte SHA-256 du contenu** (`content.hash`) | **Contenu brut du presse-papiers** (jamais stocké ni transmis) |
| 4 | `File` | `FileSystemWatcher` sur dossiers configurés (`Téléchargements`, `Bureau`, `Documents`, `Temp`) | Chemin, extension, double extension, taille, entropie statistique (0–8 bits/octet), fréquence de modifications (`FileBurst`) | **Contenu textuel ou binaire des documents** |
| 5 | `Session` | Journal Sécurité Windows (4624, 4625, 4634, 4647, 4800, 4801) | Type d'ouverture/fermeture/verrouillage, compte cible, IP source, code d'échec, horodatage | **Mots de passe**, jetons d'authentification, empreintes NTLM |
| 6 | `Device` | WMI `Win32_DeviceChangeEvent` / `Win32_PnPEntity` | Classe de périphérique (`HID`, `USBSTOR`, clavier), VID/PID, identifiant PnP | **Contenu des clés USB et supports amovibles** |
| 7 | `Browser` | Extension Manifest V3 + `Sentinel.BrowserHost` | Domaine/URL visités (sans paramètres de requête sensibles), clic sur lien externe, nombre de redirections, nom de fichier téléchargé, âge du domaine | **Contenu des pages HTML, champs de formulaires, mots de passe, cookies, sessions web** |
| 8 | `Typing` | Hook bas niveau limité aux horodatages (`Sentinel.Tray`) | **Statistiques agrégées uniquement** : vitesse moyenne (`typing.kps`), intervalle moyen/écart-type (`ms`), taille d'échantillon, indicateur d'injection synthétique (`LLKHF_INJECTED`) | **Jamais les touches frappées, ni les codes de touches, ni le texte saisi** |
| 9 | `Installation` | Registre `Uninstall`, clés `Run/RunOnce`, Planificateur de tâches | Nom/version/éditeur d'application installée, clé de démarrage, nom de tâche planifiée | Données applicatives utilisateur |
| 10 | `System` | `Sentinel.Agent` / `Sentinel.Watchdog` | Démarrage/arrêt de service, hash SHA-256 des binaires SENTINEL, alertes d'altération (`AgentTampering`) | Aucune donnée utilisateur |

---

## 3. Exclusions absolues

Les exclusions suivantes sont inscrites comme **invariants techniques non configurables** :

- **Aucun enregistrement de frappe (pas de keylogger)** : un keylogger expose les mots de passe, codes bancaires et correspondances privées et présente un risque pénal et déontologique majeur. Le collecteur `Typing` ne lit ni n'enregistre jamais les codes de touches (`vkCode`/caractères) ; il calcule uniquement les écarts temporels entre frappes afin de repérer une injection mécanique de type **BadUSB** ou macro malveillante.
- **Exclusion totale des messageries chiffrées** : le contenu de WhatsApp, Signal, Telegram, Microsoft Teams, Slack ou des clients e-mail n'est **jamais** inspecté, déchiffré ou capturé.
- **Aucune capture d'écran, webcam ou microphone** : SENTINEL ne dispose d'aucun module de capture audiovisuelle.
- **Aucune lecture de contenu de fichiers utilisateur** : le calcul d'entropie statistique et de hash sur un fichier nouvellement créé/modifié s'effectue en flux mémoire sans conserver ni indexer le texte du document.
- **Aucune conservation du presse-papiers brut** : seul le type de motif suspect (ex. URL raccourcie ou motif PowerShell encodé), le domaine éventuel et le hash SHA-256 sont conservés pour la corrélation.

---

## 4. Texte officiel de l'écran de consentement

Ce texte est affiché de manière obligatoire par `Sentinel.Installer` avant toute installation des services Windows. L'acceptation explicite (case à cocher + validation) est enregistrée avec la date UTC, l'identifiant du poste et la version de la notice dans `%ProgramData%\Sentinel\Data\consent.json`.

> ### Notice d'information et de consentement — SENTINEL
>
> **Objet du dispositif**
> Ce poste va être équipé de **SENTINEL**, un agent local de détection et de prévention des cybermenaces (phishing, logiciels malveillants, ransomwares, clés USB piégées, tentatives d'intrusion). SENTINEL complète l'antivirus système et a pour **unique finalité la sécurité informatique** ; il n'est pas utilisé pour évaluer votre productivité ou votre performance professionnelle.
>
> **Données techniques collectées (liste exhaustive)**
> L'agent collecte exclusivement des métadonnées techniques sur :
> - les lancements de processus (chemin, empreinte, signature) ;
> - les connexions réseau (adresses IP, ports, domaines, volumes) ;
> - les opérations sur fichiers dans les dossiers surveillés (chemin, extension, taille, entropie) ;
> - les ouvertures, verrouillages et échecs de session Windows ;
> - le branchement de périphériques USB (type, identifiants matériels VID/PID) ;
> - les domaines et liens ouverts dans le navigateur (si l'extension est activée) ;
> - la présence d'URL ou de commandes système à risque dans le presse-papiers (empreinte et domaine uniquement) ;
> - des statistiques anonymes de cadence de frappe (intervalles temporels uniquement, pour détecter les injections automatisées de type BadUSB) ;
> - les nouvelles installations logicielles et entrées de démarrage.
>
> **Ce que SENTINEL ne collecte JAMAIS**
> - **Aucune touche frappée** et aucun texte saisi (pas de keylogger) ;
> - **Aucun mot de passe**, formulaire web ou donnée bancaire ;
> - **Aucun contenu** de vos documents, fichiers, e-mails ou messageries (WhatsApp, Signal, Teams, etc.) ;
> - **Aucun contenu** de vos pages web, paquets réseau ou supports USB ;
> - **Aucune capture** d'écran, audio ou vidéo.
>
> **Traitement local, conservation et transparence**
> - L'analyse et l'IA fonctionnent **100 % localement** sur l'infrastructure interne ; aucune donnée n'est envoyée sur Internet.
> - Une icône visible dans la barre de notification vous indique à tout moment que SENTINEL est actif et quel mode fonctionne (Apprentissage, Simulation ou Actif).
> - Les événements techniques bruts sont purgés automatiquement après **90 jours** (par défaut) et les alertes après **12 mois**.
> - Toute consultation de votre fiche par l'administrateur sécurité est **enregistrée dans un journal d'audit infalsifiable**.
> - En cas de blocage automatique (menace critique), l'action est **réversible en un clic** par l'administrateur.
>
> **Vos droits**
> Vous disposez d'un droit d'information, d'accès et de rectification concernant les données techniques vous concernant auprès du responsable sécurité / délégué à la protection des données de votre organisation.
>
> `[ ]` *J'ai lu et compris le périmètre de collecte, les exclusions et les garanties de SENTINEL, et je consens à son installation sur ce poste.*

---

## 5. Transparence, rétention et auditabilité

### 5.1 Transparence continue

- **Icône permanente** (`Sentinel.Tray`) : indique visuellement l'état du service (`Actif`, `Apprentissage`, `Simulation`, `Déconnecté`) et permet d'ouvrir la notice de confidentialité.
- **Notifications pédagogiques** : en niveau 2 (Modéré), l'utilisateur est averti de manière explicite lorsqu'un lien ou comportement suspect est observé.

### 5.2 Politique de rétention et minimisation

Appliquée automatiquement par `RetentionCleaner` (`src/Sentinel.Storage/Services/RetentionCleaner.cs`) selon `SentinelSettings` :

| Catégorie de données | Durée par défaut | Paramètre | Comportement à l'échéance |
|---|---|---|---|
| Événements bruts (`Events`) | **90 jours** | `EventRetentionDays` | Suppression SQL définitive (`ExecuteDeleteAsync`) |
| Clusters isolés (`Clusters`, `ClusterLinks`) | **90 jours** (si aucune alerte associée) | `EventRetentionDays` | Suppression en cascade |
| Alertes et historique (`Alerts`, `AlertEvents`, `AlertHistory`) | **365 jours (12 mois)** | `AlertRetentionDays` | Suppression en cascade |
| Sessions administrateur (`AdminSessions`) | Expiration du jeton ou révocation | Durée de session | Suppression automatique |
| Journal d'audit administrateur (`AuditEntries`) | **Conservation intégrale** (non purgé automatiquement) | — | Archivage gouverné par la politique d'audit interne |

### 5.3 Journalisation des accès administrateur

Conformément à l'exigence de transparence (§2.3 de la conception) :
- Chaque consultation d'une fiche entité (`GET /api/entities/{kind}/{key}`), chaque décision sur alerte (`approve`, `reject`, `acknowledge`, `resolve`), chaque modification de paramètres (`PUT /api/settings`), chaque export de rapport et chaque connexion/déconnexion génère une entrée dans `AuditEntries`.
- Chaque entrée est chaînée cryptographiquement en SHA-256 via `HashChainWriter` et vérifiable à tout moment via `GET /api/audit/verify` (`IntegrityVerifier`).

### 5.4 Chiffrement au repos et protection des secrets

- Secrets locaux (mot de passe de la PKI mTLS, secret TOTP administrateur) chiffrés par **Windows DPAPI** (`SecretProtector`).
- Mots de passe administrateur hachés avec **PBKDF2** et sel cryptographique unique ; jetons de session stockés uniquement sous forme d'empreinte **SHA-256**.
- Fichiers mis en quarantaine déplacés hors des dossiers utilisateur vers `%ProgramData%\Sentinel\Quarantine` et chiffrés au repos.
- Recommandation de déploiement : activer **BitLocker** sur le volume système hébergeant `%ProgramData%\Sentinel\Data\sentinel.db`.

---

## 6. Cadre légal et gouvernance

Avant tout déploiement sur des postes appartenant à d'autres personnes ou en contexte professionnel, l'organisation doit faire valider la conformité juridique par un juriste ou un DPO.

### 6.1 Droit camerounais

- **Loi n° 2010/012 du 21 décembre 2010 relative à la cybersécurité et à la cybercriminalité au Cameroun** et ses textes d'application (notamment les dispositions relatives à la sécurité des systèmes d'information, à la confidentialité des communications électroniques et à la protection de la vie privée).
- Respect impératif du **secret des correspondances privées** (garanti par l'exclusion totale des messageries, e-mails et contenus de fichiers) et de l'information préalable des utilisateurs du système d'information.
- Conservation encadrée des journaux techniques de sécurité et protection contre toute altération (chaîne de hachage SHA-256).

### 6.2 Règlement Général sur la Protection des Données (RGPD — UE 2016/679)

Si le déploiement concerne des résidents ou des entités de l'Union européenne :
- **Base légale (art. 6.1.f)** : intérêt légitime de l'organisation à assurer la sécurité de son réseau et de ses informations (considérant 49 du RGPD), ou obligation légale sectorielle.
- **Minimisation et limitation de conservation (art. 5.1.c & e)** : liste fermée de métadonnées, purge automatique à 90 j / 12 mois.
- **Transparence et information (art. 13)** : notice d'information claire remise avant déploiement + écran de consentement + icône permanente.
- **Sécurité du traitement (art. 32)** : chiffrement mTLS en transit, DPAPI au repos, contrôle d'accès 2FA TOTP, journal d'audit chaîné.
- **Analyse d'Impact relative à la Protection des Données (AIPD / DPIA, art. 35)** : recommandée avant tout déploiement en entreprise sur un parc de postes utilisateurs.

### 6.3 Séparation entre supervision de sécurité et fonction RH

Si le rôle d'administrateur unique est confié à un responsable RH dans une petite structure :
- Les droits d'accès doivent être encadrés par une **charte informatique** signée et portée à la connaissance des salariés (et des instances représentatives du personnel le cas échéant).
- L'exploitation des journaux SENTINEL est **strictement limitée au traitement des incidents de sécurité** ; toute utilisation détournée pour contrôler les horaires, le volume de frappe ou la navigation non malveillante est contraire à la finalité déclarée.
- L'auditabilité complète des consultations de fiches (`AuditEntries`) protège également les utilisateurs contre tout abus de consultation.
