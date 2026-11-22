using System.Security.Claims;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;

namespace Sentinel.Server.Security;

/// <summary>
/// Middleware d'authentification par jeton Bearer (et <c>?access_token=</c> pour le hub SignalR <c>/hubs/live</c>).
/// Refuse toute requête non autorisée en dehors de la liste blanche stricte (doc §10.2).
/// </summary>
public sealed class BearerSessionMiddleware
{
    public const string TokenHashClaim = "sentinel:token_hash";
    private const string GrpcServicePrefix = "/sentinel.v1.AgentGateway/";

    private readonly RequestDelegate _next;

    public BearerSessionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AuthService authService)
    {
        if (IsAnonymousAllowed(context.Request))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var token = ExtractToken(context.Request);
        if (string.IsNullOrWhiteSpace(token))
        {
            await WriteUnauthorizedAsync(context, "UNAUTHORIZED", "Authentification Bearer requise.").ConfigureAwait(false);
            return;
        }

        var session = await authService.ValidateTokenAsync(token, context.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            await WriteUnauthorizedAsync(context, "INVALID_SESSION", "Session invalide, révoquée ou expirée.").ConfigureAwait(false);
            return;
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, session.Username),
            new Claim(TokenHashClaim, session.TokenHash)
        };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "SentinelBearer"));

        await _next(context).ConfigureAwait(false);
    }

    private static bool IsAnonymousAllowed(HttpRequest request)
    {
        if (HttpMethods.IsOptions(request.Method))
            return true;

        var path = request.Path.Value ?? string.Empty;

        // Appels gRPC agents (protégés par mTLS sur le port dédié 5181)
        if (path.StartsWith(GrpcServicePrefix, StringComparison.OrdinalIgnoreCase))
            return true;

        if (HttpMethods.IsGet(request.Method))
        {
            if (path.Equals(ApiRoutes.Ping, StringComparison.OrdinalIgnoreCase) ||
                path.Equals(ApiRoutes.AuthStatus, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        else if (HttpMethods.IsPost(request.Method))
        {
            if (path.Equals(ApiRoutes.AuthSetup, StringComparison.OrdinalIgnoreCase) ||
                path.Equals(ApiRoutes.AuthLogin, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? ExtractToken(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authHeader) &&
            authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["Bearer ".Length..].Trim();
        }

        var path = request.Path.Value ?? string.Empty;
        if (path.StartsWith(LiveHub.Path, StringComparison.OrdinalIgnoreCase) &&
            request.Query.TryGetValue("access_token", out var accessToken))
        {
            var value = accessToken.ToString().Trim();
            if (!string.IsNullOrEmpty(value))
                return value;
        }

        return null;
    }

    private static async Task WriteUnauthorizedAsync(HttpContext context, string code, string message)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json; charset=utf-8";
        var payload = SentinelJson.Serialize(new ApiError(code, message));
        await context.Response.WriteAsync(payload, context.RequestAborted).ConfigureAwait(false);
    }
}
