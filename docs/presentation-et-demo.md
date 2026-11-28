# Plan d'Action & Guide de Démonstration Live (Soutenance Jury) — SENTINEL v2.2.0

Ce guide vous fournit un **scénario de démonstration chronométré (7 à 10 minutes)** clé en main, exécutable à 100 % en local et sans aucun risque pour votre machine, afin de présenter toutes les capacités de **SENTINEL v2.2.0** devant un jury technique ou métier.

---

## 1. Préparation avant la présentation (2 minutes avant le passage)

1. **Vérifier qu'Ollama tourne localement** (optionnel mais recommandé pour montrer l'IA Qwen en direct) :
   ```powershell
   ollama list
   ```
   > SENTINEL détecte automatiquement vos modèles Qwen locaux et sélectionne **`qwen2.5-coder:3b`** sur CPU pour garantir une réponse rapide sans saturation RAM.

2. **Mettre à niveau les services Windows installés vers v2.2.0** *(à faire une seule fois si vos services étaient encore en v1.0.0)* :
   ```powershell
   .\scripts\upgrade-installed-services.ps1
   ```
   *(Ou, sans droits Administrateur, lancez une instance de démo propre sur un port dédié : `.\scripts\run-presentation-demo.ps1 -LaunchIsolatedStack` → `http://127.0.0.1:5210`).*

3. **Connectez-vous à la console** (`http://127.0.0.1:5200`), allez sur **`Scan, Audit & Démo`** (`/scan-audit`) et cliquez sur **« 🧹 Nettoyer le bruit historique (doublons) »** pour partir d'un tableau de bord parfaitement propre.

---

## 2. Déroulé de démonstration en 6 étapes (8 minutes)

### Étape 1 — Architecture & IA Locale Qwen adaptative (1 min)
- Montrez le bandeau supérieur :
  - **Mode Actif / Apprentissage / Simulation**.
  - Pastille **`IA : qwen2.5-coder:3b`** verte (en ligne).
- Allez dans **`Paramètres`** (`/settings`) → section **IA locale Ollama** :
  - Montrez les modèles Qwen détectés sur le PC, le **cache sémantique TTL** (`< 0,1 ms` sur rafales), le `keep_alive` et cliquez sur **« Re-détecter le meilleur Qwen »**.

### Étape 2 — Notifications temps réel In-App, Email, SMS, WhatsApp & Webhook (1 min 30)
- Restez dans **`Paramètres`** → section **Notifications administrateur par criticité** :
  - Montrez le routage indépendant par seuil (`Faible`, `Modéré`, `Élevé`, `Critique`) sur **In-App**, **Email SMTP**, **SMS (Twilio / Passerelle HTTP)**, **WhatsApp (Meta Cloud / Twilio)** et **Slack / Teams / Telegram**.
  - Soulignez que tous les mots de passe/jetons sont chiffrés via **Windows DPAPI** (zéro secret dans SQLite).
  - Cliquez sur **« 🔔 Tester Notification App »** : la **cloche en haut à droite** s'incrémente instantanément en temps réel via SignalR !

### Étape 3 — Démonstration d'une chaîne d'attaque & du nouvel Arbre Causal (2 min)
- Ouvrez **`Scan, Audit & Démo`** (`/scan-audit`).
- Cliquez sur **« ▶ Lancer ce scénario »** sur la carte **1. Chaîne Phishing → PowerShell → C2**.
- En moins de 2 secondes :
  - Une notification temps réel apparaît dans la **cloche** en haut à droite (avec signal sonore discret).
  - Cliquez sur **« 🌳 Voir l'Arbre Causal → »** :
    - Montrez la hiérarchie claire de gauche à droite : **`POSTE (pc-compta-01)`** → **`COMPTE (a.kamga)`** → **`PROCESSUS (Bulletin_Paie_Nov.pdf.exe → powershell.exe)`** → **`ÉVÉNEMENTS`** → **`DOMAINE / IP C2 (185.220.101.45:4444)`** → **`MENACE CORRÉLÉE`**.
    - Montrez la différence visuelle entre les **flèches pleines bleues (`──▶` flux causal direct)** et les **flèches pointillées violettes (`- -▶` corrélation indirecte inter-étapes)**.
    - Cliquez sur n'importe quel nœud : toute sa branche amont/aval s'illumine et le panneau latéral affiche ses métadonnées complètes.
    - Basculez le sélecteur sur **« ⚡ Flux chronologique temps réel »** puis revenez à **« 🌳 Arbre causal »**, et tapez `powershell` dans la **recherche instantanée**.

### Étape 4 — Intervention de l'IA Qwen & Réponse Réversible sur Rançongiciel (2 min)
- Retournez sur **`Scan, Audit & Démo`** (`/scan-audit`) et lancez **2. Rançongiciel & Fichier Canari**.
- Cliquez sur **« ⚠️ Ouvrir l'Alerte & IA → »** (`/alerts/{id}`) :
  - Montrez les tags **MITRE ATT&CK (`T1486`, `T1204.002`)** et la chronologie des événements.
  - Cliquez sur **« ✨ Diagnostic & Plan d'Action IA (Qwen) »** : l'IA locale synthétise la cause racine, les actions immédiates et le plan de durcissement, **sans jamais déclencher d'action seule**.
  - Dans la colonne de droite (**Actions & blocages liés**), montrez la réversibilité garantie en 1 clic (**`↩ Annuler le blocage`**).

### Étape 5 — Scan Système Général & Audit de Posture Cryptographique (1 min 30)
- Sur **`Scan, Audit & Démo`** (`/scan-audit`) :
  - Cliquez sur **« 🔍 Lancer un Scan Système Général »** : inspection réelle de tous les processus actifs du PC, des connexions TCP établies, des clés de registre `Run`/`RunOnce`, des binaires récents (YARA + PeNet + ML PE) et des fichiers canaris.
  - Cliquez sur **« 🛡️ Exécuter l'Audit de Sécurité »** : affiche le **Score de Posture `/100`** sur 11 contrôles (Defender temps réel, Pare-feu 3 profils, UAC, PowerShell 4104, Sysmon, **vérification cryptographique SHA-256 de `sentinel.db`**, PKI mTLS, règles Sigma/YARA, ML, Qwen IA).

### Étape 6 — Preuve de Confidentialité (*Privacy by Design*) & Export PDF (30 s)
- Rappelez le scénario **BadUSB** : SENTINEL détecte une frappe injectée à `68 touches/s` uniquement grâce aux **intervalles de temps en millisecondes**, sans jamais enregistrer une seule touche ni aucun texte du presse-papiers.
- Sur **`Rapports & Évaluation`** (`/reports`), téléchargez un rapport **PDF** complet et montrez le benchmark scientifique **A vs B vs C (`-55 %` sur le Time-To-Detect, `0 %` de faux positifs)**.
