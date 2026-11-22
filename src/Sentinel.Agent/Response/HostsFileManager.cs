using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Agent.Response;

/// <summary>
/// Gère le blocage réversible de domaines dans le fichier <c>hosts</c> Windows au sein d'une section dédiée
/// <c># &gt;&gt;&gt; SENTINEL BLOCKED DOMAINS &gt;&gt;&gt;</c>. Restaure le fichier à l'octet près lorsque tous
/// les domaines bloqués sont retirés. Le chemin est injectable pour les tests unitaires.
/// </summary>
public sealed partial class HostsFileManager
{
    public const string StartMarker = "# >>> SENTINEL BLOCKED DOMAINS >>>";
    public const string EndMarker = "# <<< SENTINEL BLOCKED DOMAINS <<<";
    private const string NoTrailingEolTag = " [no-eol]";

    private readonly string _hostsPath;
    private readonly object _gate = new();

    public string HostsFilePath => _hostsPath;

    public HostsFileManager(string? hostsFilePath = null)
    {
        _hostsPath = string.IsNullOrWhiteSpace(hostsFilePath)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts")
            : hostsFilePath;
    }

    public bool BlockDomain(string domain)
    {
        var normalized = NormalizeDomain(domain);
        if (normalized is null)
        {
            throw new ArgumentException($"Nom de domaine invalide ou interdit au blocage : « {domain} ».", nameof(domain));
        }

        lock (_gate)
        {
            var content = File.Exists(_hostsPath) ? File.ReadAllText(_hostsPath, Encoding.UTF8) : string.Empty;
            var eol = DetectLineEnding(content);
            var parsed = ParseSection(content);

            if (parsed.Domains.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }

            var updatedDomains = parsed.Domains.ToList();
            updatedDomains.Add(normalized);
            WriteContent(parsed.Before, updatedDomains, parsed.After, parsed.TrimLeadingEolOnRemove, eol);
            return true;
        }
    }

    public bool UnblockDomain(string domain)
    {
        var normalized = NormalizeDomain(domain);
        if (normalized is null)
        {
            return false;
        }

        lock (_gate)
        {
            if (!File.Exists(_hostsPath))
            {
                return false;
            }

            var content = File.ReadAllText(_hostsPath, Encoding.UTF8);
            var eol = DetectLineEnding(content);
            var parsed = ParseSection(content);

            var remaining = parsed.Domains
                .Where(d => !d.Equals(normalized, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (remaining.Count == parsed.Domains.Count)
            {
                return false;
            }

            WriteContent(parsed.Before, remaining, parsed.After, parsed.TrimLeadingEolOnRemove, eol);
            return true;
        }
    }

    public IReadOnlyList<string> GetBlockedDomains()
    {
        lock (_gate)
        {
            if (!File.Exists(_hostsPath))
            {
                return Array.Empty<string>();
            }

            try
            {
                var content = File.ReadAllText(_hostsPath, Encoding.UTF8);
                return ParseSection(content).Domains;
            }
            catch
            {
                return Array.Empty<string>();
            }
        }
    }

    public static string? NormalizeDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var trimmed = raw.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            trimmed = uri.Host;
        }

        trimmed = trimmed.Trim().TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length is < 3 or > 253)
        {
            return null;
        }

        if (trimmed is "localhost" or "127.0.0.1" or "::1" || trimmed.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return ValidDomainRegex().IsMatch(trimmed) ? trimmed : null;
    }

    private void WriteContent(string before, List<string> domains, string after, bool trimLeadingEolOnRemove, string eol)
    {
        var dir = Path.GetDirectoryName(_hostsPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string finalContent;
        if (domains.Count == 0)
        {
            if (trimLeadingEolOnRemove)
            {
                before = StripSingleTrailingEol(before);
            }
            finalContent = before + after;
        }
        else
        {
            var needsLeadingEol = before.Length > 0 && !before.EndsWith('\n');
            var markTrim = trimLeadingEolOnRemove || needsLeadingEol;

            var sb = new StringBuilder(before.Length + domains.Count * 32 + after.Length + 128);
            sb.Append(before);
            if (needsLeadingEol)
            {
                sb.Append(eol);
            }

            sb.Append(StartMarker).Append(eol);
            foreach (var d in domains)
            {
                sb.Append("0.0.0.0 ").Append(d).Append(eol);
            }
            sb.Append(EndMarker);
            if (markTrim)
            {
                sb.Append(NoTrailingEolTag);
            }
            sb.Append(eol);
            sb.Append(after);
            finalContent = sb.ToString();
        }

        File.WriteAllText(_hostsPath, finalContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static ParsedHostsSection ParseSection(string content)
    {
        var startIdx = content.IndexOf(StartMarker, StringComparison.Ordinal);
        if (startIdx < 0)
        {
            return new ParsedHostsSection(content, [], string.Empty, false);
        }

        var endIdx = content.IndexOf(EndMarker, startIdx + StartMarker.Length, StringComparison.Ordinal);
        if (endIdx < 0)
        {
            return new ParsedHostsSection(content, [], string.Empty, false);
        }

        var endLineEnd = content.IndexOf('\n', endIdx);
        var endLineText = endLineEnd >= 0
            ? content[endIdx..endLineEnd].TrimEnd('\r')
            : content[endIdx..];
        var trimLeading = endLineText.EndsWith(NoTrailingEolTag, StringComparison.Ordinal);
        var afterStart = endLineEnd >= 0 ? endLineEnd + 1 : content.Length;

        var before = content[..startIdx];
        var bodyStart = content.IndexOf('\n', startIdx);
        var body = (bodyStart >= 0 && bodyStart < endIdx)
            ? content[(bodyStart + 1)..endIdx]
            : string.Empty;
        var after = content[afterStart..];

        var domains = new List<string>();
        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                var dom = NormalizeDomain(parts[1]);
                if (dom is not null && !domains.Contains(dom, StringComparer.OrdinalIgnoreCase))
                {
                    domains.Add(dom);
                }
            }
        }

        return new ParsedHostsSection(before, domains, after, trimLeading);
    }

    private static string DetectLineEnding(string content) =>
        content.Contains("\r\n", StringComparison.Ordinal) || !content.Contains('\n') ? "\r\n" : "\n";

    private static string StripSingleTrailingEol(string value)
    {
        if (value.EndsWith("\r\n", StringComparison.Ordinal)) return value[..^2];
        if (value.EndsWith('\n')) return value[..^1];
        return value;
    }

    [GeneratedRegex(@"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")]
    private static partial Regex ValidDomainRegex();

    private sealed record ParsedHostsSection(
        string Before,
        List<string> Domains,
        string After,
        bool TrimLeadingEolOnRemove);
}
