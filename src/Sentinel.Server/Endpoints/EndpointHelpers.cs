using System.Security.Claims;
using Sentinel.Server.Security;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;

namespace Sentinel.Server.Endpoints;

internal static class EndpointHelpers
{
    public static string GetActor(HttpContext context) =>
        context.User.FindFirstValue(ClaimTypes.Name) ?? "admin";

    public static string? GetTokenHash(HttpContext context) =>
        context.User.FindFirstValue(BearerSessionMiddleware.TokenHashClaim);

    public static string? GetClientIp(HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString();

    public static (int Page, int PageSize) NormalizePaging(int? page, int? pageSize, int defaultSize = 25, int maxSize = 200)
    {
        var p = page.GetValueOrDefault(1);
        if (p < 1) p = 1;
        var ps = pageSize.GetValueOrDefault(defaultSize);
        if (ps < 1) ps = defaultSize;
        if (ps > maxSize) ps = maxSize;
        return (p, ps);
    }

    public static TEnum? TryParseEnum<TEnum>(string? value) where TEnum : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Enum.TryParse<TEnum>(value.Trim(), ignoreCase: true, out var parsed) ? parsed : null;
    }

    public static async Task<T?> ReadOptionalJsonAsync<T>(HttpRequest request, CancellationToken ct) where T : class
    {
        if (!request.HasJsonContentType())
            return null;

        if (request.ContentLength is 0)
            return null;

        try
        {
            return await request.ReadFromJsonAsync<T>(SentinelJson.Options, ct).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    public static IResult Error(int statusCode, string code, string message) =>
        Results.Json(new ApiError(code, message), SentinelJson.Options, statusCode: statusCode);
}
