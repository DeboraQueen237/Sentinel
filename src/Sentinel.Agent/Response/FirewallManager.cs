using System.Diagnostics;
using System.Net;

namespace Sentinel.Agent.Response;

/// <summary>
/// Gestionnaire de règles pare-feu Windows réversibles via <c>netsh advfirewall</c> (doc §9.2, §9.3).
/// Toutes les règles créées portent le préfixe <c>Sentinel_Block_</c> afin d'être supprimées proprement
/// lors d'une annulation (« Revert »).
/// </summary>
public sealed class FirewallManager
{
    public const string RulePrefix = "Sentinel_Block_";

    public static string BuildRuleName(string id)
    {
        var safe = new string((id ?? Guid.NewGuid().ToString("N"))
            .Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-')
            .ToArray());
        if (string.IsNullOrWhiteSpace(safe))
        {
            safe = Guid.NewGuid().ToString("N");
        }
        return RulePrefix + safe[..Math.Min(safe.Length, 48)];
    }

    public async Task<(bool Success, string RuleName, string Message)> BlockIpAsync(string ruleId, string ipAddress, CancellationToken ct)
    {
        if (!IPAddress.TryParse(ipAddress?.Trim(), out var parsed) || IPAddress.IsLoopback(parsed))
        {
            return (false, string.Empty, $"Adresse IP invalide ou boucle locale protégée : « {ipAddress} ».");
        }

        var ruleName = BuildRuleName(ruleId);
        var outRes = await RunNetshAsync(
            ["advfirewall", "firewall", "add", "rule", $"name={ruleName}", "dir=out", "action=block", $"remoteip={parsed}"],
            ct);
        if (!outRes.Success)
        {
            return (false, ruleName, outRes.Output);
        }

        var inRes = await RunNetshAsync(
            ["advfirewall", "firewall", "add", "rule", $"name={ruleName}", "dir=in", "action=block", $"remoteip={parsed}"],
            ct);
        return (inRes.Success, ruleName, inRes.Success ? $"Règle pare-feu {ruleName} créée pour l'IP {parsed}." : inRes.Output);
    }

    public async Task<(bool Success, string RuleName, string Message)> BlockProgramAsync(string ruleId, string programPath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(programPath) || !File.Exists(programPath))
        {
            return (false, string.Empty, $"Exécutable introuvable pour le blocage pare-feu : « {programPath} ».");
        }

        var fullPath = Path.GetFullPath(programPath);
        var ruleName = BuildRuleName(ruleId);
        var res = await RunNetshAsync(
            ["advfirewall", "firewall", "add", "rule", $"name={ruleName}", "dir=out", "action=block", $"program={fullPath}"],
            ct);
        return (res.Success, ruleName, res.Success ? $"Trafic sortant bloqué pour {fullPath} (règle {ruleName})." : res.Output);
    }

    public async Task<(bool Success, string RuleName, string Message)> IsolateHostAsync(string ruleId, CancellationToken ct)
    {
        // Bloque tout trafic sortant hors boucle locale (127.0.0.0/8) pour préserver la communication locale gRPC/Admin.
        var ruleName = BuildRuleName("Isolate_" + ruleId);
        var res = await RunNetshAsync(
            [
                "advfirewall", "firewall", "add", "rule",
                $"name={ruleName}",
                "dir=out",
                "action=block",
                "remoteip=0.0.0.1-126.255.255.255,128.0.0.0-255.255.255.255"
            ],
            ct);
        return (res.Success, ruleName, res.Success ? $"Poste isolé du réseau externe (règle {ruleName}, boucle locale préservée)." : res.Output);
    }

    public async Task<(bool Success, string Message)> RemoveRuleAsync(string ruleName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.Ordinal))
        {
            return (false, $"Nom de règle SENTINEL invalide : « {ruleName} ».");
        }

        var res = await RunNetshAsync(
            ["advfirewall", "firewall", "delete", "rule", $"name={ruleName}"],
            ct);
        return (res.Success, res.Success ? $"Règle pare-feu {ruleName} supprimée." : res.Output);
    }

    private static async Task<(bool Success, string Output)> RunNetshAsync(string[] args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe"),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var a in args)
            {
                psi.ArgumentList.Add(a);
            }

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "Impossible de lancer netsh.exe.");
            }

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            var stderr = await proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            var combined = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : $"{stdout.Trim()} {stderr.Trim()}".Trim();
            return (proc.ExitCode == 0, combined);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
