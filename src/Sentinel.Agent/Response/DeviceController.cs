using System.Diagnostics;

namespace Sentinel.Agent.Response;

/// <summary>
/// Désactivation et réactivation réversible de périphériques PnP (ex. BadUSB) via <c>pnputil.exe</c> (doc §9.2).
/// </summary>
public sealed class DeviceController
{
    public Task<(bool Success, string Message)> DisableDeviceAsync(string instanceId, CancellationToken ct) =>
        RunPnpUtilAsync("/disable-device", instanceId, ct);

    public Task<(bool Success, string Message)> EnableDeviceAsync(string instanceId, CancellationToken ct) =>
        RunPnpUtilAsync("/enable-device", instanceId, ct);

    private static async Task<(bool Success, string Message)> RunPnpUtilAsync(string verb, string instanceId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(instanceId))
        {
            return (false, "Identifiant d'instance PnP manquant.");
        }

        var trimmed = instanceId.Trim();
        if (trimmed.Any(c => c is '\r' or '\n' or '"' or '&' or '|' or ';'))
        {
            return (false, $"Identifiant d'instance PnP invalide : « {trimmed} ».");
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pnputil.exe"),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(verb);
            psi.ArgumentList.Add(trimmed);

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "Impossible de lancer pnputil.exe.");
            }

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            var stderr = await proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            var msg = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : $"{stdout.Trim()} {stderr.Trim()}".Trim();
            return (proc.ExitCode == 0, string.IsNullOrWhiteSpace(msg) ? $"pnputil {verb} exécuté." : msg);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
