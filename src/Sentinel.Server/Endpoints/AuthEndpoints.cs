using Microsoft.AspNetCore.Mvc;
using Sentinel.Server.Security;
using Sentinel.Shared.Api;

namespace Sentinel.Server.Endpoints;

internal static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.AuthStatus, async (AuthService auth, CancellationToken ct) =>
        {
            var status = await auth.GetStatusAsync(ct).ConfigureAwait(false);
            return Results.Ok(status);
        });

        app.MapPost(ApiRoutes.AuthSetup, async ([FromBody] SetupRequest request, HttpContext ctx, AuthService auth, CancellationToken ct) =>
        {
            var result = await auth.SetupAsync(request, EndpointHelpers.GetClientIp(ctx), ct).ConfigureAwait(false);
            if (result.Success)
                return Results.Ok(result.Value);

            return result.FailureKind switch
            {
                AuthFailureKind.AlreadyConfigured => EndpointHelpers.Error(StatusCodes.Status409Conflict, result.ErrorCode!, result.ErrorMessage!),
                _ => EndpointHelpers.Error(StatusCodes.Status400BadRequest, result.ErrorCode ?? "INVALID_REQUEST", result.ErrorMessage ?? "Requête invalide.")
            };
        });

        app.MapPost(ApiRoutes.AuthLogin, async ([FromBody] LoginRequest request, HttpContext ctx, AuthService auth, CancellationToken ct) =>
        {
            var result = await auth.LoginAsync(request, EndpointHelpers.GetClientIp(ctx), ct).ConfigureAwait(false);
            if (result.Success)
                return Results.Ok(result.Value);

            return result.FailureKind switch
            {
                AuthFailureKind.LockedOut => EndpointHelpers.Error(StatusCodes.Status429TooManyRequests, result.ErrorCode ?? "ACCOUNT_LOCKED", result.ErrorMessage ?? "Compte temporairement verrouillé."),
                _ => EndpointHelpers.Error(StatusCodes.Status401Unauthorized, result.ErrorCode ?? "UNAUTHORIZED", result.ErrorMessage ?? "Authentification échouée.")
            };
        });

        app.MapPost(ApiRoutes.AuthLogout, async (HttpContext ctx, AuthService auth, CancellationToken ct) =>
        {
            var tokenHash = EndpointHelpers.GetTokenHash(ctx);
            if (!string.IsNullOrWhiteSpace(tokenHash))
            {
                await auth.LogoutAsync(tokenHash, EndpointHelpers.GetActor(ctx), EndpointHelpers.GetClientIp(ctx), ct).ConfigureAwait(false);
            }
            return Results.NoContent();
        });

        app.MapPost(ApiRoutes.AuthChangePassword, async ([FromBody] ChangePasswordRequest request, HttpContext ctx, AuthService auth, CancellationToken ct) =>
        {
            var tokenHash = EndpointHelpers.GetTokenHash(ctx) ?? string.Empty;
            var result = await auth.ChangePasswordAsync(tokenHash, request, EndpointHelpers.GetClientIp(ctx), ct).ConfigureAwait(false);
            if (result.Success)
                return Results.NoContent();

            return result.FailureKind switch
            {
                AuthFailureKind.Unauthorized => EndpointHelpers.Error(StatusCodes.Status401Unauthorized, result.ErrorCode!, result.ErrorMessage!),
                _ => EndpointHelpers.Error(StatusCodes.Status400BadRequest, result.ErrorCode ?? "INVALID_REQUEST", result.ErrorMessage ?? "Requête invalide.")
            };
        });
    }
}
