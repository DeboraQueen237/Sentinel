using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.Shared.Security;

/// <summary>
/// PKI locale de SENTINEL pour le mTLS agent ↔ serveur (doc §11) :
/// une autorité racine auto-signée génère un certificat serveur et un certificat client « agent ».
/// Les PFX sont protégés par un mot de passe aléatoire lui-même chiffré par DPAPI (portée machine).
/// </summary>
public static class SentinelPki
{
    public const string CaFile = "sentinel-ca.pfx";
    public const string CaPublicFile = "sentinel-ca.cer";
    public const string ServerFile = "sentinel-server.pfx";
    public const string AgentFile = "sentinel-agent.pfx";
    private const string PasswordSecretName = "pki-password";

    private static readonly object Gate = new();

    /// <summary>Crée les certificats s'ils n'existent pas. Idempotent.</summary>
    public static void EnsureCertificates(string? directory = null)
    {
        var dir = directory ?? Infrastructure.SentinelPaths.Certificates;
        lock (Gate)
        {
            Directory.CreateDirectory(dir);
            var password = SecretProtector.GetOrCreateSecret(PasswordSecretName);
            var caPath = Path.Combine(dir, CaFile);

            X509Certificate2 ca;
            if (!File.Exists(caPath))
            {
                ca = CreateCa();
                File.WriteAllBytes(caPath, ca.Export(X509ContentType.Pfx, password));
                File.WriteAllBytes(Path.Combine(dir, CaPublicFile), ca.Export(X509ContentType.Cert));
                // Un nouveau CA invalide les anciens certificats feuilles
                TryDelete(Path.Combine(dir, ServerFile));
                TryDelete(Path.Combine(dir, AgentFile));
            }
            else
            {
                ca = X509CertificateLoader.LoadPkcs12FromFile(caPath, password, X509KeyStorageFlags.Exportable);
            }

            using (ca)
            {
                var serverPath = Path.Combine(dir, ServerFile);
                if (!File.Exists(serverPath))
                {
                    using var server = CreateLeaf(ca, "CN=Sentinel Server", isServer: true);
                    File.WriteAllBytes(serverPath, server.Export(X509ContentType.Pfx, password));
                }
                var agentPath = Path.Combine(dir, AgentFile);
                if (!File.Exists(agentPath))
                {
                    using var agent = CreateLeaf(ca, "CN=Sentinel Agent", isServer: false);
                    File.WriteAllBytes(agentPath, agent.Export(X509ContentType.Pfx, password));
                }
            }
        }
    }

    public static X509Certificate2 LoadServerCertificate(string? directory = null) => Load(ServerFile, directory);
    public static X509Certificate2 LoadAgentCertificate(string? directory = null) => Load(AgentFile, directory);

    public static X509Certificate2 LoadCaCertificate(string? directory = null)
    {
        var dir = directory ?? Infrastructure.SentinelPaths.Certificates;
        return X509CertificateLoader.LoadCertificateFromFile(Path.Combine(dir, CaPublicFile));
    }

    /// <summary>Valide qu'un certificat distant est émis par la CA SENTINEL (trust store personnalisé).</summary>
    public static bool ValidateIssuedBy(X509Certificate2? certificate, X509Certificate2 ca)
    {
        if (certificate is null) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        var ok = chain.Build(certificate);
        return ok && chain.ChainElements[^1].Certificate.Thumbprint == ca.Thumbprint;
    }

    private static X509Certificate2 Load(string file, string? directory)
    {
        var dir = directory ?? Infrastructure.SentinelPaths.Certificates;
        var password = SecretProtector.GetOrCreateSecret(PasswordSecretName);
        var path = Path.Combine(dir, file);
        try
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        }
    }

    private static X509Certificate2 CreateCa()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Sentinel Local CA, O=Sentinel", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string subject, bool isServer)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject + ", O=Sentinel", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            isServer ? new Oid("1.3.6.1.5.5.7.3.1") /* serverAuth */ : new Oid("1.3.6.1.5.5.7.3.2") /* clientAuth */
        }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        if (isServer)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            san.AddDnsName(Environment.MachineName);
            san.AddIpAddress(IPAddress.Loopback);
            san.AddIpAddress(IPAddress.IPv6Loopback);
            req.CertificateExtensions.Add(san.Build());
        }
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var signed = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5), serial);
        return signed.CopyWithPrivateKey(key);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* ignoré */ }
    }
}
