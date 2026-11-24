using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Sentinel.Shared.Security;

/// <summary>Résultat d'application d'ACL NTFS restrictives sur un dossier SENTINEL.</summary>
public sealed record AclHardeningResult(bool Applied, string Path, string Message);

/// <summary>
/// Durcissement NTFS des répertoires sensibles de SENTINEL (v2 Mission 9 — threat-model.md) :
/// restreint l'accès de <c>%ProgramData%\Sentinel</c> (et sous-dossiers Data, Certs, Secrets, Quarantine)
/// exclusivement à <c>SYSTEM</c> et <c>Administrateurs</c>, sans héritage permissif.
/// </summary>
public static class DirectorySecurityHardener
{
    /// <summary>
    /// Applique des ACL restrictives (SYSTEM + Administrateurs uniquement) sur <paramref name="directoryPath"/>.
    /// Tolérant en mode non-élevé (développement/tests) : retourne <c>Applied = false</c> sans lever d'exception fatale.
    /// </summary>
    public static AclHardeningResult HardenDirectory(string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return new AclHardeningResult(false, string.Empty, "Chemin vide.");
        }

        try
        {
            Directory.CreateDirectory(directoryPath);
            if (!OperatingSystem.IsWindows())
            {
                return new AclHardeningResult(false, directoryPath, "ACL NTFS applicables uniquement sur Windows.");
            }

            return ApplyWindowsAcl(directoryPath);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new AclHardeningResult(false, directoryPath, $"Privilèges insuffisants pour durcir les ACL ({ex.Message}).");
        }
        catch (Exception ex)
        {
            return new AclHardeningResult(false, directoryPath, $"Durcissement ACL non appliqué : {ex.Message}");
        }
    }

    [SupportedOSPlatform("windows")]
    private static AclHardeningResult ApplyWindowsAcl(string directoryPath)
    {
        // En mode non-élevé (ex. dotnet run sous jeton UAC filtré), retirer l'utilisateur courant
        // verrouillerait immédiatement le processus lui-même hors de son propre répertoire de données.
        // Le durcissement strict SYSTEM + Administrateurs ne s'applique qu'en contexte Service (SYSTEM)
        // ou Administrateur élevé (installateur / service Windows).
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        var isElevatedOrSystem = identity.IsSystem || principal.IsInRole(WindowsBuiltInRole.Administrator);
        if (!isElevatedOrSystem)
        {
            return new AclHardeningResult(
                false,
                directoryPath,
                "Processus non élevé (mode développement) : durcissement NTFS SYSTEM+Administrateurs réservé aux services Windows et à l'installateur élevé.");
        }

        var dirInfo = new DirectoryInfo(directoryPath);
        var security = dirInfo.GetAccessControl();

        // Supprime l'héritage permissif (ex. Users en lecture/écriture)
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var existingRules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in existingRules)
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        security.AddAccessRule(new FileSystemAccessRule(
            systemSid,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            adminsSid,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        dirInfo.SetAccessControl(security);
        return new AclHardeningResult(true, directoryPath, "ACL NTFS restrictives appliquées (SYSTEM + Administrateurs uniquement).");
    }

    /// <summary>Calcule une signature HMAC-SHA256 sur le manifeste d'intégrité à l'aide d'une clé protégée localement.</summary>
    public static string SignManifestPayload(string payload, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        using var hmac = new HMACSHA256(key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
    }

    /// <summary>Vérifie en temps constant la signature HMAC-SHA256 d'un manifeste d'intégrité.</summary>
    public static bool VerifyManifestSignature(string payload, string expectedHex, byte[] key)
    {
        if (string.IsNullOrWhiteSpace(expectedHex) || key is null || key.Length == 0) return false;
        var actual = SignManifestPayload(payload, key);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actual),
            Encoding.ASCII.GetBytes(expectedHex.Trim().ToLowerInvariant()));
    }
}
