using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Shared.Security;

/// <summary>Protection des secrets au repos via DPAPI (doc §11).</summary>
public static class SecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Sentinel.v1.secret-entropy");

    /// <summary>
    /// Chiffre avec DPAPI. <paramref name="machineScope"/> = true : déchiffrable par tout processus de la machine
    /// (nécessaire pour partager entre services LocalSystem et outils admin) ; false : utilisateur courant uniquement.
    /// </summary>
    public static byte[] Protect(byte[] data, bool machineScope = true)
    {
        if (!OperatingSystem.IsWindows()) return data;
        return ProtectedData.Protect(data, Entropy, machineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
    }

    public static byte[] Unprotect(byte[] data, bool machineScope = true)
    {
        if (!OperatingSystem.IsWindows()) return data;
        return ProtectedData.Unprotect(data, Entropy, machineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
    }

    public static string ProtectString(string value, bool machineScope = true) =>
        Convert.ToBase64String(Protect(Encoding.UTF8.GetBytes(value), machineScope));

    public static string UnprotectString(string value, bool machineScope = true) =>
        Encoding.UTF8.GetString(Unprotect(Convert.FromBase64String(value), machineScope));

    /// <summary>Lit (ou crée) un secret aléatoire persistant protégé par DPAPI dans <c>SentinelPaths.Secrets</c>.</summary>
    public static string GetOrCreateSecret(string name, int bytes = 32)
    {
        var file = Path.Combine(Infrastructure.SentinelPaths.Secrets, name + ".dpapi");
        if (File.Exists(file))
        {
            return UnprotectString(File.ReadAllText(file));
        }
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));
        File.WriteAllText(file, ProtectString(secret));
        return secret;
    }
}

/// <summary>Chaîne de hash pour l'intégrité des journaux (doc §3.2, §11) : H(n) = SHA256(H(n-1) | payload).</summary>
public static class HashChain
{
    public static readonly string Genesis = new('0', 64);

    public static string Compute(string previousHash, string payload)
    {
        var bytes = Encoding.UTF8.GetBytes(previousHash + "|" + payload);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static bool Verify(string previousHash, string payload, string expectedHash) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Compute(previousHash, payload)),
            Encoding.ASCII.GetBytes(expectedHash ?? string.Empty));

    public static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public static string Sha256File(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }
}
