using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;

namespace Sentinel.Simulation.Replay;

/// <summary>
/// Envoie les résultats d'évaluation (<see cref="ScenarioMetricDto"/>[]) vers l'API REST
/// <c>POST /api/reports/evaluation</c> de <c>Sentinel.Server</c> pour affichage dans la console Admin.
/// </summary>
public static class EvaluationApiPusher
{
    public static async Task<bool> PushAsync(
        string apiBaseUrl,
        string? bearerToken,
        IReadOnlyList<ScenarioMetricDto> metrics,
        CancellationToken ct = default)
    {
        var endpoint = apiBaseUrl.TrimEnd('/') + ApiRoutes.Evaluation;

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);

            if (!string.IsNullOrWhiteSpace(bearerToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken.Trim());
            }

            var json = JsonSerializer.Serialize(metrics, SentinelJson.Options);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");

            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"  [API] ✔ {metrics.Count} métriques d'évaluation publiées sur {endpoint} (HTTP {(int)response.StatusCode}).");
                return true;
            }

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            Console.Error.WriteLine($"  [API] Échec de publication sur {endpoint} : HTTP {(int)response.StatusCode} ({response.ReasonPhrase}). {body}");
            return false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"  [API] Erreur de connexion vers {endpoint} : {ex.Message}");
            return false;
        }
    }
}
