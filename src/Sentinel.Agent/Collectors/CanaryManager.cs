using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>Enregistrement persistant d'un fichier canari déployé.</summary>
public sealed record CanaryRecord(
    string Id,
    string FilePath,
    string Folder,
    string ExpectedSha256,
    long SizeBytes,
    DateTimeOffset DeployedAt);

/// <summary>Résultat de vérification d'un fichier canari.</summary>
public sealed record CanaryCheckFinding(
    CanaryRecord Record,
    string EventType,
    string? ObservedSha256,
    double? ObservedEntropy,
    string Reason);

/// <summary>
/// Gestionnaire des fichiers canari anti-ransomware (v2 Mission 6) :
/// déploie discrètement des fichiers leurres crédibles (noms, tailles et horodatages réalistes,
/// sans aucun contenu personnel), enregistre leurs empreintes SHA-256 et vérifie leur intégrité.
/// </summary>
public sealed class CanaryManager
{
    private static readonly (string FileName, string Kind, int TargetBytes)[] DecoyTemplates =
    [
        ("Budget_Previsionnel_2026.csv", "csv", 24_576),
        ("Factures_Archive_Trimestre.rtf", "rtf", 32_768),
        ("Notes_Projet_Synthese.txt", "txt", 18_432),
        ("Inventaire_Reference_2026.xml", "xml", 28_672)
    ];

    private readonly string _registryPath;
    private readonly ILogger<CanaryManager> _logger;
    private readonly object _gate = new();
    private List<CanaryRecord> _records = new();

    public CanaryManager(ILogger<CanaryManager>? logger = null, string? registryPath = null)
    {
        _logger = logger ?? NullLogger<CanaryManager>.Instance;
        _registryPath = string.IsNullOrWhiteSpace(registryPath) ? SentinelPaths.CanariesRegistryFile : registryPath;
        LoadRegistry();
    }

    public IReadOnlyList<CanaryRecord> Records
    {
        get
        {
            lock (_gate) return _records.ToArray();
        }
    }

    /// <summary>Déploie les fichiers canari manquants dans les dossiers configurés.</summary>
    public IReadOnlyList<CanaryRecord> EnsureDeployed(CanarySettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.Enabled)
        {
            return Records;
        }

        var filesPerFolder = Math.Clamp(settings.FilesPerFolder, 1, DecoyTemplates.Length);
        var folders = settings.Folders
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(f => Environment.ExpandEnvironmentVariables(f.Trim()))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        lock (_gate)
        {
            var changed = false;

            foreach (var folder in folders)
            {
                if (!Directory.Exists(folder))
                {
                    continue;
                }

                for (var i = 0; i < filesPerFolder; i++)
                {
                    var tpl = DecoyTemplates[i];
                    var fullPath = Path.Combine(folder, tpl.FileName);
                    var existing = _records.FirstOrDefault(r =>
                        r.FilePath.Equals(fullPath, StringComparison.OrdinalIgnoreCase));

                    if (existing is not null && File.Exists(fullPath))
                    {
                        continue;
                    }

                    // Ne jamais écraser un fichier utilisateur préexistant non enregistré par SENTINEL
                    if (existing is null && File.Exists(fullPath))
                    {
                        continue;
                    }

                    try
                    {
                        var bytes = BuildRealisticDecoyBytes(tpl.Kind, tpl.TargetBytes, fullPath);
                        File.WriteAllBytes(fullPath, bytes);

                        // Horodatage crédible (quelques semaines dans le passé) pour éviter un marquage trivial
                        var backdated = DateTime.UtcNow.AddDays(-17 - i * 9);
                        File.SetCreationTimeUtc(fullPath, backdated);
                        File.SetLastWriteTimeUtc(fullPath, backdated.AddHours(3));

                        var sha256 = ComputeSha256Hex(bytes);
                        var record = new CanaryRecord(
                            Id: existing?.Id ?? $"CAN-{Guid.NewGuid().ToString("N")[..8].ToUpperInvariant()}",
                            FilePath: fullPath,
                            Folder: folder,
                            ExpectedSha256: sha256,
                            SizeBytes: bytes.LongLength,
                            DeployedAt: DateTimeOffset.UtcNow);

                        if (existing is not null)
                        {
                            _records.Remove(existing);
                        }
                        _records.Add(record);
                        changed = true;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Impossible de déployer le fichier canari dans {Folder}.", folder);
                    }
                }
            }

            if (changed)
            {
                SaveRegistryLocked();
            }

            return _records.ToArray();
        }
    }

    /// <summary>Vérifie l'intégrité de tous les fichiers canari enregistrés.</summary>
    public IReadOnlyList<CanaryCheckFinding> VerifyAll()
    {
        var findings = new List<CanaryCheckFinding>();
        IReadOnlyList<CanaryRecord> snapshot;
        lock (_gate) snapshot = _records.ToArray();

        foreach (var rec in snapshot)
        {
            var finding = VerifySingle(rec);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }
        return findings;
    }

    public CanaryCheckFinding? VerifySingle(CanaryRecord rec)
    {
        if (!File.Exists(rec.FilePath))
        {
            return new CanaryCheckFinding(
                rec,
                EventTypes.CanaryDeleted,
                null,
                null,
                $"Fichier canari supprimé ou déplacé : {rec.FilePath}");
        }

        try
        {
            var bytes = File.ReadAllBytes(rec.FilePath);
            var actualHash = ComputeSha256Hex(bytes);
            if (actualHash.Equals(rec.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var entropy = ComputeShannonEntropy(bytes);
            var isEncrypted = entropy >= 7.2;
            var eventType = isEncrypted ? EventTypes.CanaryEncrypted : EventTypes.CanaryModified;
            var reason = isEncrypted
                ? $"Fichier canari chiffré (entropie {entropy:F2} bits/octet, empreinte altérée) : {rec.FilePath}"
                : $"Fichier canari modifié de manière non autorisée (empreinte altérée) : {rec.FilePath}";

            return new CanaryCheckFinding(rec, eventType, actualHash, entropy, reason);
        }
        catch (Exception ex)
        {
            return new CanaryCheckFinding(
                rec,
                EventTypes.CanaryModified,
                null,
                null,
                $"Fichier canari verrouillé ou inaccessible ({ex.Message}) : {rec.FilePath}");
        }
    }

    public CanaryRecord? FindByPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        lock (_gate)
        {
            return _records.FirstOrDefault(r => r.FilePath.Equals(path, StringComparison.OrdinalIgnoreCase));
        }
    }

    public IReadOnlyList<CanaryStatusDto> GetStatuses(string hostId)
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<CanaryRecord> snapshot;
        lock (_gate) snapshot = _records.ToArray();

        var result = new List<CanaryStatusDto>(snapshot.Count);
        foreach (var rec in snapshot)
        {
            var finding = VerifySingle(rec);
            result.Add(new CanaryStatusDto(
                rec.Id,
                hostId,
                rec.FilePath,
                rec.Folder,
                rec.ExpectedSha256,
                rec.SizeBytes,
                Intact: finding is null,
                rec.DeployedAt,
                now,
                Status: finding is null ? "Intact" : finding.EventType));
        }
        return result;
    }

    /// <summary>Supprime proprement tous les fichiers canari déployés (désactivation ou désinstallation).</summary>
    public int RemoveAll()
    {
        var removed = 0;
        lock (_gate)
        {
            foreach (var rec in _records)
            {
                try
                {
                    if (File.Exists(rec.FilePath))
                    {
                        File.Delete(rec.FilePath);
                        removed++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Échec de suppression du canari {Path}.", rec.FilePath);
                }
            }

            _records.Clear();
            SaveRegistryLocked();
        }
        return removed;
    }

    internal static byte[] BuildRealisticDecoyBytes(string kind, int targetBytes, string seedKey)
    {
        var sb = new StringBuilder(targetBytes + 512);
        switch (kind)
        {
            case "csv":
                sb.AppendLine("Reference;Departement;Periode;Montant_EUR;Statut");
                for (var i = 1; sb.Length < targetBytes; i++)
                {
                    sb.AppendLine($"REF-2026-{i:D4};Operations;Q{((i - 1) % 4) + 1};{(1250 + (i * 37) % 9400)}.00;Valide");
                }
                break;

            case "rtf":
                sb.Append(@"{\rtf1\ansi\deff0{\fonttbl{\f0 Calibri;}}\f0\fs22 ");
                sb.AppendLine(@"Synthese documentaire interne - Archive de reference.\par");
                for (var i = 1; sb.Length < targetBytes - 8; i++)
                {
                    sb.AppendLine($@"Ligne {i:D4} : suivi de dossier trimestriel, verification comptable et rapprochement administratif standard.\par");
                }
                sb.Append('}');
                break;

            case "xml":
                sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
                sb.AppendLine("<Inventaire annee=\"2026\">");
                for (var i = 1; sb.Length < targetBytes - 32; i++)
                {
                    sb.AppendLine($"  <Article code=\"ART-{i:D5}\" categorie=\"Fournitures\" quantite=\"{(i % 25) + 1}\" />");
                }
                sb.AppendLine("</Inventaire>");
                break;

            default:
                sb.AppendLine("Compte rendu de synthese - Suivi projet interne 2026");
                sb.AppendLine(new string('-', 60));
                for (var i = 1; sb.Length < targetBytes; i++)
                {
                    sb.AppendLine($"Point {i:D3} : avancement nominal des livrables planifies, revue de qualite et validation equipe.");
                }
                break;
        }

        // Empreinte déterministe discrète par poste/chemin afin que chaque canari soit unique
        sb.Append($"<!-- ref:{ComputeSha256Hex(Encoding.UTF8.GetBytes(seedKey))[..12]} -->");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public static string ComputeSha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> freq = stackalloc int[256];
        foreach (var b in data) freq[b]++;

        double entropy = 0;
        double len = data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            var p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return Math.Round(entropy, 3);
    }

    private void LoadRegistry()
    {
        try
        {
            if (!File.Exists(_registryPath)) return;
            var json = File.ReadAllText(_registryPath);
            var loaded = SentinelJson.Deserialize<List<CanaryRecord>>(json);
            if (loaded is not null)
            {
                _records = loaded;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Impossible de charger le registre des canaris depuis {Path}.", _registryPath);
        }
    }

    private void SaveRegistryLocked()
    {
        try
        {
            var dir = Path.GetDirectoryName(_registryPath);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_registryPath, SentinelJson.Serialize(_records));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Impossible de sauvegarder le registre des canaris dans {Path}.", _registryPath);
        }
    }
}
