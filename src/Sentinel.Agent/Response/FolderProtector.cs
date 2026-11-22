using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Agent.Response;

/// <summary>
/// Applique ou retire une protection en lecture seule réversible (ACL Deny Write/Delete)
/// sur les dossiers utilisateur en cas de suspicion critique de ransomware (doc §9.2, §9.3).
/// </summary>
public sealed class FolderProtector
{
    private const FileSystemRights DenyWriteRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles;

    public (bool Success, List<string> ProtectedFolders, string AccountSid, string Message) Protect(IEnumerable<string> folders)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
                  ?? new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value;
        var identity = new SecurityIdentifier(sid);
        var rule = new FileSystemAccessRule(
            identity,
            DenyWriteRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Deny);

        var applied = new List<string>();
        var errors = new List<string>();

        foreach (var raw in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var expanded = Environment.ExpandEnvironmentVariables(raw);
                if (!Directory.Exists(expanded))
                {
                    continue;
                }

                var dirInfo = new DirectoryInfo(expanded);
                var acl = dirInfo.GetAccessControl();
                acl.AddAccessRule(rule);
                dirInfo.SetAccessControl(acl);
                applied.Add(expanded);
            }
            catch (Exception ex)
            {
                errors.Add($"{raw}: {ex.Message}");
            }
        }

        if (applied.Count == 0)
        {
            return (false, applied, sid, errors.Count > 0 ? string.Join(" ; ", errors) : "Aucun dossier valide à protéger.");
        }

        return (true, applied, sid, $"{applied.Count} dossier(s) protégé(s) en écriture.");
    }

    public (bool Success, string Message) Unprotect(IEnumerable<string> folders, string accountSid)
    {
        var identity = !string.IsNullOrWhiteSpace(accountSid)
            ? new SecurityIdentifier(accountSid)
            : new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

        var rule = new FileSystemAccessRule(
            identity,
            DenyWriteRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Deny);

        var restored = 0;
        var errors = new List<string>();

        foreach (var path in folders)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    continue;
                }

                var dirInfo = new DirectoryInfo(path);
                var acl = dirInfo.GetAccessControl();
                acl.RemoveAccessRuleSpecific(rule);
                dirInfo.SetAccessControl(acl);
                restored++;
            }
            catch (Exception ex)
            {
                errors.Add($"{path}: {ex.Message}");
            }
        }

        return errors.Count == 0
            ? (true, $"Protection retirée sur {restored} dossier(s).")
            : (restored > 0, $"Protection retirée sur {restored} dossier(s) ; erreurs : {string.Join(" ; ", errors)}");
    }
}
