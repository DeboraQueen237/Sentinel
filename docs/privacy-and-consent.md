# Vie privée, éthique, consentement et cadre légal (v2)

> Document de gouvernance et de conformité de **SENTINEL v2.0.0** — mis à jour pour l'ensemble des canaux de détection v2 et vérifié par test automatisé de la base SQLite.

---

## 1. Principes fondateurs (*Privacy by Design*)

1. **Finalité unique de cybersécurité** : SENTINEL détecte des menaces techniques et ne sert jamais à mesurer la productivité ou l'activité rédactionnelle d'un utilisateur.
2. **Traitement 100 % local** : analyse, corrélation, ML PE, YARA, Sigma et IA (`Ollama` `qwen2.5-coder:3b`) tournent localement. **Aucune donnée utilisateur n'est transmise vers un service cloud** (seuls des flux entrants publics de Threat Intelligence opt-in téléchargent des listes d'IOC ; VirusTotal est strictement opt-in, à la demande, et n'envoie qu'un hash SHA-256).
3. **Liste fermée de métadonnées** : aucun texte saisi, aucun contenu de document, aucun message chiffré, aucune capture d'écran/audio/vidéo.
4. **Preuve technique automatisée** : le test d'intégration `V2HardeningAndDetectionEndpointsTests.PrivacyInvariant_SqlLiteDatabaseMustContainZeroRawUserContent` vérifie à chaque build que la base `sentinel.db` ne contient aucun secret, texte brut de presse-papiers ou contenu utilisateur après ingestion.

---

## 2. Périmètre complet des canaux collectés (v1 + v2)

| # | Catégorie (`EventCategory`) | Mécanisme | Métadonnées conservées | Données strictement exclues |
|---|---|---|---|---|
| 1 | `Process` | ETW / WMI | Nom, chemin, PID, parent, ligne de commande, SHA-256, signature Authenticode | Mémoire RAM, variables d'environnement |
| 2 | `Network` | ETW TCPIP / DNS / `IPGlobalProperties` | IP/port, protocole, direction, volumes, domaine DNS | **Payload des paquets**, corps HTTP/TLS |
| 3 | `Clipboard` | `Sentinel.Tray` | Type de motif (`url`/`command`), domaine, raccourcisseur, **hash SHA-256** | **Texte brut du presse-papiers** |
| 4 | `File` | `FileSystemWatcher` dossiers surveillés | Chemin, extension, double extension, taille, entropie (0–8), fréquence | **Contenu des documents** |
| 5 | `Session` | Journal Sécurité (`4624`–`4801`) | Type d'ouverture/échec/verrouillage, compte cible, IP source, horodatage | **Mots de passe**, jetons, hashes NTLM |
| 6 | `Device` | WMI USB/PnP | Classe (`HID`/`USBSTOR`), VID/PID, identifiant PnP | **Contenu des supports USB** |
| 7 | `Browser` | Extension MV3 + `BrowserHost` | Domaine/URL (sans query sensible), redirections, nom de téléchargement | **Contenu HTML, formulaires, cookies, mots de passe** |
| 8 | `Typing` | Hook horodatages uniquement (`Sentinel.Tray`) | Cadence (`kps`), intervalle moyen/écart-type (`ms`), drapeau `LLKHF_INJECTED` | **Jamais les touches ni le texte saisi** |
| 9 | `Installation` | Registre `Uninstall`/`Run`, tâches planifiées | Nom d'application, clé de démarrage, nom de tâche | Données applicatives |
| 10 | `System` | `Agent` / `Watchdog` | État/suppression de service, hash SHA-256 binaires SENTINEL | Aucune donnée utilisateur |
| 11 | `Defender` *(v2)* | WMI `MSFT_Mp*` + `Defender/Operational` | Nom/gravité de menace Defender, action appliquée, ajout d'exclusion, arrêt temps réel | Contenu des fichiers analysés |
| 12 | `Script` *(v2)* | PowerShell `4104` + ETW AMSI optionnel | **Par défaut** : ID de bloc, hash SHA-256, longueur, entropie, score d'obfuscation, indicateurs détectés. **Opt-in uniquement** : extrait ≤ 300 car. avec caviardage automatique des secrets (`Bearer`, `Password`, clés API) | Corps complet des scripts et secrets |
| 13 | `Canary` *(v2)* | `CanaryManager` / `CanaryCollector` | Chemin du fichier leurre géré par SENTINEL, hash attendu vs observé, entropie | Fichiers personnels de l'utilisateur |
| 14 | `StaticAnalysis` *(v2)* | `StaticFileScanner` (YARA + `PeNet` + ML) | Nom de règle YARA, métadonnées PE (sections, imports, packer, signature), compteurs statistiques agrégés | **Aucune chaîne textuelle extraite du binaire**, aucun contenu de document |
| 15 | `ThreatIntel` *(v2)* | `ReputationService` (SQLite + Bloom local) | Indicateur IOC public (hash/domaine/URL/IP), source (`URLhaus`, etc.), date | Toute donnée locale vers l'extérieur |

---

## 3. Exclusions absolues (invariants non configurables)

- **Aucun keylogger** : jamais de capture de codes de touches ni de texte frappé.
- **Aucune inspection de messageries chiffrées** (WhatsApp, Signal, Telegram, Teams, Slack, e-mails).
- **Aucune capture d'écran, webcam ou microphone**.
- **Aucun envoi de fichiers utilisateur sur Internet** (même avec VirusTotal activé, seul le hash SHA-256 est interrogé sur demande explicite de l'administrateur).
- **Notifications externes strictement opt-in (v2.1)** : les canaux administrateur (**Email SMTP**, **WhatsApp Meta Cloud/Twilio**, **Webhook/Slack/Teams/Telegram**) sont **désactivés par défaut**. Lorsqu'un administrateur les active explicitement, seules les **métadonnées d'alerte assainies** (criticité, score, nom de poste, type de menace, tags MITRE, résumé technique) sont transmises — jamais de fichiers, mots de passe, frappes ou texte du presse-papiers. Tous les jetons/mots de passe sont chiffrés localement par Windows DPAPI.
- **Aucune suppression définitive automatique** : toute quarantaine est réversible.

---

## 4. Consentement explicite, transparence et rétention

- **Écran de consentement obligatoire** (`Sentinel.Installer`) : acceptation horodatée et signée SHA-256 dans `%ProgramData%\Sentinel\Data\consent.json`, précisant la liste fermée v1+v2 et les exclusions absolues.
- **Icône permanente** (`Sentinel.Tray`) affichant le mode courant (`Apprentissage`, `Simulation`, `Actif`).
- **Rétention automatique (`RetentionCleaner`)** : 90 jours pour les événements bruts (`Events`), 365 jours pour les alertes (`Alerts`), conservation gouvernée pour `AuditEntries` (journal chaîné SHA-256 de tous les accès administrateur).
- **Cadre légal** : compatible avec les principes de minimisation et transparence de la **Loi camerounaise n° 2010/012** (cybersécurité et cybercriminalité) et du **RGPD (UE 2016/679)** (art. 5, 6.1.f, 13, 32, 35 — validation juridique/DPO recommandée avant déploiement sur un parc d'entreprise).
