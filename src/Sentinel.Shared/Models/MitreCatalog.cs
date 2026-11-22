namespace Sentinel.Shared.Models;

/// <summary>Référence MITRE ATT&amp;CK (doc §14.4) pour l'explicabilité, le dashboard et les rapports.</summary>
public sealed record MitreTechniqueInfo(string Id, string Name, string Tactic, string Description);

public static class MitreCatalog
{
    private static readonly Dictionary<string, MitreTechniqueInfo> Techniques = new(StringComparer.OrdinalIgnoreCase)
    {
        ["T1566"] = new("T1566", "Phishing", "Initial Access", "Hameçonnage par lien ou pièce jointe malveillante."),
        ["T1566.002"] = new("T1566.002", "Spearphishing Link", "Initial Access", "Lien malveillant ciblé (souvent raccourci ou domaine récent)."),
        ["T1204"] = new("T1204", "User Execution", "Execution", "Exécution d'un fichier ou lien malveillant par l'utilisateur."),
        ["T1204.002"] = new("T1204.002", "Malicious File", "Execution", "Exécution d'un binaire ou script téléchargé."),
        ["T1059"] = new("T1059", "Command and Scripting Interpreter", "Execution", "Exécution via interpréteur de commandes (PowerShell, cmd, WSH)."),
        ["T1059.001"] = new("T1059.001", "PowerShell", "Execution", "Abus de PowerShell (commande encodée, contournement politique)."),
        ["T1059.003"] = new("T1059.003", "Windows Command Shell", "Execution", "Exécution suspecte via cmd.exe."),
        ["T1218"] = new("T1218", "System Binary Proxy Execution", "Defense Evasion", "Exécution détournée via LOLBins (mshta, rundll32, regsvr32, certutil)."),
        ["T1036"] = new("T1036", "Masquerading", "Defense Evasion", "Usurpation de nom ou double extension (ex. facture.pdf.exe)."),
        ["T1036.007"] = new("T1036.007", "Double File Extension", "Defense Evasion", "Masquage d'un exécutable derrière une extension documentaire."),
        ["T1486"] = new("T1486", "Data Encrypted for Impact", "Impact", "Chiffrement massif de fichiers caractéristique d'un ransomware."),
        ["T1052"] = new("T1052", "Exfiltration Over Physical Medium", "Exfiltration", "Exfiltration de données via support amovible USB."),
        ["T1041"] = new("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Envoi de volumes anormaux vers un serveur externe."),
        ["T1560"] = new("T1560", "Archive Collected Data", "Collection", "Création d'archive avant exfiltration."),
        ["T1110"] = new("T1110", "Brute Force", "Credential Access", "Tentatives répétées d'authentification échouées."),
        ["T1078"] = new("T1078", "Valid Accounts", "Initial Access", "Connexion réussie suspecte ou hors horaires habituels."),
        ["T1200"] = new("T1200", "Hardware Additions", "Initial Access", "Branchement d'un périphérique matériel suspect (BadUSB / clavier HID)."),
        ["T1056"] = new("T1056", "Input Capture / Injection", "Collection", "Anomalie de dynamique de saisie (frappe scriptée ou injectée)."),
        ["T1547"] = new("T1547", "Boot or Logon Autostart Execution", "Persistence", "Ajout d'une entrée de démarrage automatique (registre Run/RunOnce)."),
        ["T1547.001"] = new("T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "Persistance via clé de registre de démarrage."),
        ["T1053"] = new("T1053", "Scheduled Task/Job", "Persistence", "Création d'une tâche planifiée à des fins de persistance."),
        ["T1053.005"] = new("T1053.005", "Scheduled Task", "Persistence", "Persistance via le Planificateur de tâches Windows."),
        ["T1071"] = new("T1071", "Application Layer Protocol", "Command and Control", "Communication sortante vers un domaine ou une IP rare/suspecte."),
        ["T1105"] = new("T1105", "Ingress Tool Transfer", "Command and Control", "Téléchargement d'un outil ou charge utile externe."),
        ["T1562"] = new("T1562", "Impair Defenses", "Defense Evasion", "Tentative d'arrêt, de désactivation ou d'altération de SENTINEL ou de Defender."),
        ["T1562.001"] = new("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Désactivation de la protection temps réel ou ajout d'exclusions Microsoft Defender."),
        ["T1562.006"] = new("T1562.006", "Indicator Blocking", "Defense Evasion", "Tentative de contournement de la journalisation PowerShell / AMSI."),
        ["T1027"] = new("T1027", "Obfuscated Files or Information", "Defense Evasion", "Encodage, obfuscation ou empaquetage de scripts ou exécutables."),
        ["T1027.002"] = new("T1027.002", "Software Packing", "Defense Evasion", "Binaire PE compressé ou protégé par un packer (UPX, entropie élevée)."),
        ["T1140"] = new("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "Décodage à la volée (certutil, base64, PowerShell)."),
        ["T1218.005"] = new("T1218.005", "Mshta", "Defense Evasion", "Exécution de contenu HTA ou script distant via mshta.exe."),
        ["T1218.010"] = new("T1218.010", "Regsvr32", "Defense Evasion", "Exécution détournée via regsvr32.exe (Squiblydoo)."),
        ["T1218.011"] = new("T1218.011", "Rundll32", "Defense Evasion", "Exécution de DLL ou script via rundll32.exe."),
        ["T1197"] = new("T1197", "BITS Jobs", "Defense Evasion", "Téléchargement ou persistance via bitsadmin / BITS."),
        ["T1047"] = new("T1047", "Windows Management Instrumentation", "Execution", "Exécution de commande ou processus via WMIC / WMI."),
        ["T1003"] = new("T1003", "OS Credential Dumping", "Credential Access", "Tentative d'accès aux secrets ou au processus LSASS."),
        ["T1490"] = new("T1490", "Inhibit System Recovery", "Impact", "Suppression des clichés instantanés (vssadmin, wbadmin, bcdedit).")
    };

    public static MitreTechniqueInfo? TryGet(string id) =>
        Techniques.TryGetValue(id, out var info) ? info : null;

    public static MitreTechniqueInfo GetOrDefault(string id) =>
        TryGet(id) ?? new MitreTechniqueInfo(id, id, "Unknown", "Technique MITRE ATT&CK.");

    public static IReadOnlyCollection<MitreTechniqueInfo> All => Techniques.Values;
}
