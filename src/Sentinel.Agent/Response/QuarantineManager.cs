using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Security;

namespace Sentinel.Agent.Response;

/// <summary>Enregistrement de quarantaine réversible stocké dans le ticket d'action (doc §9.3).</summary>
public sealed record QuarantineRecord(
    string QuarantineId,
    string OriginalPath,
    string OriginalSha256,
    long OriginalSize,
    string QuarantinedFilePath,
    string MetadataPath,
    DateTimeOffset QuarantinedAtUtc);

/// <summary>
/// Gestionnaire de quarantaine chiffrée réversible (doc §9.2, §9.3) :
/// déplace le fichier suspect vers <see cref="SentinelPaths.Quarantine"/> en le chiffrant par blocs
/// AES-256-GCM avec une clé aléatoire protégée par DPAPI. Aucune suppression définitive n'est jamais effectuée.
/// </summary>
public sealed class QuarantineManager
{
    private const int ChunkSize = 64 * 1024;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] MagicHeader = "SNTQ1"u8.ToArray();

    private readonly string _quarantineDir;

    public QuarantineManager(string? quarantineDirectory = null)
    {
        _quarantineDir = quarantineDirectory ?? SentinelPaths.Quarantine;
        Directory.CreateDirectory(_quarantineDir);
    }

    public QuarantineRecord Quarantine(string sourceFilePath)
    {
        if (string.IsNullOrWhiteSpace(sourceFilePath))
        {
            throw new ArgumentException("Chemin de fichier invalide.", nameof(sourceFilePath));
        }

        var fullSource = Path.GetFullPath(sourceFilePath);
        if (!File.Exists(fullSource))
        {
            throw new FileNotFoundException("Fichier introuvable pour la mise en quarantaine.", fullSource);
        }

        Directory.CreateDirectory(_quarantineDir);

        var fileInfo = new FileInfo(fullSource);
        var originalSize = fileInfo.Length;
        var originalSha256 = HashChain.Sha256File(fullSource);
        var quarantineId = Guid.NewGuid().ToString("N");

        var qbinPath = Path.Combine(_quarantineDir, quarantineId + ".qbin");
        var metaPath = Path.Combine(_quarantineDir, quarantineId + ".meta.json");

        var aesKey = RandomNumberGenerator.GetBytes(32);
        var baseNonce = RandomNumberGenerator.GetBytes(NonceSize);

        try
        {
            EncryptFileChunked(fullSource, qbinPath, aesKey, baseNonce, quarantineId);

            var protectedKey = Convert.ToBase64String(SecretProtector.Protect(aesKey, machineScope: true));
            var now = DateTimeOffset.UtcNow;

            var metadata = new QuarantineMetadata(
                quarantineId,
                fullSource,
                originalSha256,
                originalSize,
                protectedKey,
                now);

            File.WriteAllText(metaPath, SentinelJson.Serialize(metadata));

            // Supprime l'original uniquement une fois le fichier chiffré et ses métadonnées validés sur disque.
            File.Delete(fullSource);

            return new QuarantineRecord(
                quarantineId,
                fullSource,
                originalSha256,
                originalSize,
                qbinPath,
                metaPath,
                now);
        }
        catch
        {
            TryDelete(qbinPath);
            TryDelete(metaPath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    public string Restore(string quarantineId, string? overrideDestinationPath = null)
    {
        if (string.IsNullOrWhiteSpace(quarantineId))
        {
            throw new ArgumentException("Identifiant de quarantaine invalide.", nameof(quarantineId));
        }

        var qbinPath = Path.Combine(_quarantineDir, quarantineId + ".qbin");
        var metaPath = Path.Combine(_quarantineDir, quarantineId + ".meta.json");

        if (!File.Exists(metaPath) || !File.Exists(qbinPath))
        {
            throw new FileNotFoundException($"Entrée de quarantaine « {quarantineId} » introuvable.", qbinPath);
        }

        var metadata = SentinelJson.Deserialize<QuarantineMetadata>(File.ReadAllText(metaPath))
            ?? throw new InvalidDataException("Métadonnées de quarantaine corrompues.");

        var destination = string.IsNullOrWhiteSpace(overrideDestinationPath)
            ? metadata.OriginalPath
            : Path.GetFullPath(overrideDestinationPath);

        var destDir = Path.GetDirectoryName(destination);
        if (!string.IsNullOrWhiteSpace(destDir))
        {
            Directory.CreateDirectory(destDir);
        }

        var aesKey = SecretProtector.Unprotect(Convert.FromBase64String(metadata.ProtectedKeyBase64), machineScope: true);
        var tempRestore = destination + ".sentinel-restore.tmp";

        try
        {
            DecryptFileChunked(qbinPath, tempRestore, aesKey, metadata.QuarantineId);

            var restoredSha = HashChain.Sha256File(tempRestore);
            if (!string.Equals(restoredSha, metadata.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("L'empreinte SHA-256 du fichier restauré ne correspond pas à l'original.");
            }

            File.Move(tempRestore, destination, overwrite: true);
            TryDelete(qbinPath);
            TryDelete(metaPath);
            return destination;
        }
        catch
        {
            TryDelete(tempRestore);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    private static void EncryptFileChunked(string sourcePath, string destPath, byte[] key, byte[] baseNonce, string quarantineId)
    {
        using var aes = new AesGcm(key, TagSize);
        using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize);
        using var output = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize);

        output.Write(MagicHeader);
        output.Write(baseNonce);

        var plainBuffer = new byte[ChunkSize];
        var cipherBuffer = new byte[ChunkSize];
        var tag = new byte[TagSize];
        var lenPrefix = new byte[4];
        var chunkNonce = new byte[NonceSize];
        ulong chunkIndex = 0;

        while (true)
        {
            var bytesRead = input.Read(plainBuffer, 0, plainBuffer.Length);
            if (bytesRead <= 0 && chunkIndex > 0)
            {
                break;
            }

            DeriveChunkNonce(baseNonce, chunkIndex, chunkNonce);
            var aad = Encoding.UTF8.GetBytes($"SNTQ1|{quarantineId}|{chunkIndex}");

            aes.Encrypt(
                chunkNonce,
                plainBuffer.AsSpan(0, bytesRead),
                cipherBuffer.AsSpan(0, bytesRead),
                tag,
                aad);

            BinaryPrimitives.WriteInt32LittleEndian(lenPrefix, bytesRead);
            output.Write(lenPrefix);
            output.Write(tag);
            if (bytesRead > 0)
            {
                output.Write(cipherBuffer, 0, bytesRead);
            }

            chunkIndex++;
            if (bytesRead == 0)
            {
                break;
            }
        }

        output.Flush(flushToDisk: true);
    }

    private static void DecryptFileChunked(string sourcePath, string destPath, byte[] key, string quarantineId)
    {
        using var aes = new AesGcm(key, TagSize);
        using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize);
        using var output = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize);

        var header = new byte[MagicHeader.Length];
        input.ReadExactly(header);
        if (!header.AsSpan().SequenceEqual(MagicHeader))
        {
            throw new InvalidDataException("Format de fichier en quarantaine non reconnu.");
        }

        var baseNonce = new byte[NonceSize];
        input.ReadExactly(baseNonce);

        var lenPrefix = new byte[4];
        var tag = new byte[TagSize];
        var chunkNonce = new byte[NonceSize];
        var cipherBuffer = new byte[ChunkSize];
        var plainBuffer = new byte[ChunkSize];
        ulong chunkIndex = 0;

        while (input.Position < input.Length)
        {
            input.ReadExactly(lenPrefix);
            var plainLen = BinaryPrimitives.ReadInt32LittleEndian(lenPrefix);
            if (plainLen < 0 || plainLen > ChunkSize)
            {
                throw new InvalidDataException("Taille de bloc chiffré invalide.");
            }

            input.ReadExactly(tag);
            if (plainLen > 0)
            {
                input.ReadExactly(cipherBuffer.AsSpan(0, plainLen));
            }

            DeriveChunkNonce(baseNonce, chunkIndex, chunkNonce);
            var aad = Encoding.UTF8.GetBytes($"SNTQ1|{quarantineId}|{chunkIndex}");

            aes.Decrypt(
                chunkNonce,
                cipherBuffer.AsSpan(0, plainLen),
                tag,
                plainBuffer.AsSpan(0, plainLen),
                aad);

            if (plainLen > 0)
            {
                output.Write(plainBuffer, 0, plainLen);
            }

            chunkIndex++;
        }

        output.Flush(flushToDisk: true);
    }

    private static void DeriveChunkNonce(byte[] baseNonce, ulong chunkIndex, Span<byte> destination)
    {
        baseNonce.CopyTo(destination);
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(counter, chunkIndex);
        for (int i = 0; i < 8; i++)
        {
            destination[NonceSize - 8 + i] ^= counter[i];
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* ignoré */ }
    }

    private sealed record QuarantineMetadata(
        string QuarantineId,
        string OriginalPath,
        string OriginalSha256,
        long OriginalSize,
        string ProtectedKeyBase64,
        DateTimeOffset QuarantinedAtUtc);
}
