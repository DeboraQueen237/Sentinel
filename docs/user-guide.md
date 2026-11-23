# Guide utilisateur poste — SENTINEL v2

> Guide de transparence destiné aux utilisateurs d'un poste Windows protégé par **SENTINEL v2**.

---

## 1. À quoi sert SENTINEL sur votre poste ?

**SENTINEL** est un outil local de cybersécurité qui complète **Microsoft Defender** pour détecter tôt les attaques progressives (liens de phishing, clés USB piégées BadUSB, ransomwares, scripts obfusqués). Il ne sert **jamais** à mesurer votre productivité ou votre temps de travail.

---

## 2. L'icône SENTINEL dans la barre de notification (`Sentinel.Tray`)

L'icône reste visible en permanence près de l'horloge Windows pour vous informer de l'état de la protection :
- **Apprentissage** *(7 premiers jours par défaut)* : SENTINEL apprend vos usages habituels (logiciels courants, horaires) et n'effectue **aucun blocage automatique**.
- **Simulation** : les alertes sont enregistrées pour test sans aucune action sur votre poste.
- **Actif** : en cas de menace critique confirmée (ex. chiffrement de fichiers par un ransomware), SENTINEL peut isoler ou mettre en quarantaine de façon **réversible en un clic** par l'administrateur.

---

## 3. Notifications de sensibilisation

En cas de lien suspect (raccourcisseur inconnu, domaine créé il y a quelques jours, fichier à double extension comme `facture.pdf.exe`), une notification discrète vous invite à vérifier la provenance avant d'ouvrir le fichier.

---

## 4. Vos garanties de vie privée

Ce que SENTINEL **ne collecte JAMAIS** :
- **Aucune touche frappée au clavier** ni texte saisi (pas de keylogger ; seules des statistiques de cadence servent à détecter une clé USB malveillante injectant 75 touches/seconde).
- **Aucun mot de passe**, formulaire web ou coordonnée bancaire.
- **Aucun contenu** de vos documents (Word, Excel, PDF), e-mails ou messageries chiffrées (WhatsApp, Signal, Teams, etc.).
- **Aucune capture** d'écran, webcam ou microphone.
- **Aucun transfert vers le cloud** : l'analyse et l'IA tournent 100 % localement.

En cas de faux positif (fichier légitime bloqué en quarantaine), contactez votre administrateur sécurité : toute action automatique est **réversible en un clic** sans perte de données.
