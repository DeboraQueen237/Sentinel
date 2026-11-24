using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;
using Sentinel.Server.Configuration;
using Sentinel.Shared.Api;
using Sentinel.Shared.Security;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Security;

public enum AuthFailureKind
{
    None = 0,
    BadRequest = 1,
    AlreadyConfigured = 2,
    Unauthorized = 3,
    LockedOut = 4
}

public sealed record AuthResult<T>(bool Success, T? Value, AuthFailureKind FailureKind = AuthFailureKind.None, string? ErrorCode = null, string? ErrorMessage = null)
{
    public static AuthResult<T> Ok(T value) => new(true, value);
    public static AuthResult<T> Fail(AuthFailureKind kind, string code, string message) => new(false, default, kind, code, message);
}

public sealed record AuthenticatedSession(string Username, string TokenHash, DateTimeOffset ExpiresAt);

/// <summary>
/// Service d'authentification du compte administrateur unique (doc §10.2) :
/// PBKDF2-HMAC-SHA256 (600 000 itérations, sel 32 octets), 2FA TOTP (Otp.NET, secret protégé par DPAPI),
/// et sessions courtes stockées uniquement sous forme d'empreinte SHA-256.
/// </summary>
public sealed class AuthService
{
    private const int Pbkdf2Iterations = 600_000;
    private const int SaltBytes = 32;
    private const int HashBytes = 32;
    private const int TokenBytes = 32;
    private const int TotpSecretBytes = 20;
    private const int MinPasswordLength = 8;
    public const int MaxFailedLoginAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly HashChainWriter _auditWriter;
    private readonly IOptions<SentinelServerOptions> _options;
    private readonly ILogger<AuthService> _logger;
    private readonly SemaphoreSlim _setupGate = new(1, 1);
    private readonly object _lockoutGate = new();
    private readonly Dictionary<string, LoginAttemptTracker> _failedAttempts = new(StringComparer.OrdinalIgnoreCase);

    public AuthService(
        IDbContextFactory<SentinelDbContext> dbFactory,
        HashChainWriter auditWriter,
        IOptions<SentinelServerOptions> options,
        ILogger<AuthService> logger)
    {
        _dbFactory = dbFactory;
        _auditWriter = auditWriter;
        _options = options;
        _logger = logger;
    }

    public async Task<AuthStatusDto> GetStatusAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var admin = await db.AdminUsers
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == AdminUserEntity.SingletonId, ct)
            .ConfigureAwait(false);

        return admin is null
            ? new AuthStatusDto(false, null)
            : new AuthStatusDto(true, admin.Username);
    }

    public async Task<AuthResult<SetupResponse>> SetupAsync(SetupRequest request, string? ipAddress, CancellationToken ct = default)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return AuthResult<SetupResponse>.Fail(AuthFailureKind.BadRequest, "INVALID_INPUT", "Nom d'utilisateur et mot de passe requis.");
        }

        var username = request.Username.Trim();
        if (username.Length < 3 || username.Length > 64)
        {
            return AuthResult<SetupResponse>.Fail(AuthFailureKind.BadRequest, "INVALID_USERNAME", "Le nom d'utilisateur doit contenir entre 3 et 64 caractères.");
        }

        if (request.Password.Length < MinPasswordLength)
        {
            return AuthResult<SetupResponse>.Fail(AuthFailureKind.BadRequest, "WEAK_PASSWORD", $"Le mot de passe doit contenir au moins {MinPasswordLength} caractères.");
        }

        await _setupGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var exists = await db.AdminUsers.AnyAsync(u => u.Id == AdminUserEntity.SingletonId, ct).ConfigureAwait(false);
            if (exists)
            {
                return AuthResult<SetupResponse>.Fail(AuthFailureKind.AlreadyConfigured, "ALREADY_CONFIGURED", "Le compte administrateur est déjà configuré.");
            }

            var (hash, salt) = HashPassword(request.Password);
            var totpKey = KeyGeneration.GenerateRandomKey(TotpSecretBytes);
            var base32Secret = Base32Encoding.ToString(totpKey);
            var totpProtected = SecretProtector.ProtectString(base32Secret);
            var now = DateTimeOffset.UtcNow;

            var entity = new AdminUserEntity
            {
                Id = AdminUserEntity.SingletonId,
                Username = username,
                PasswordHash = hash,
                PasswordSalt = salt,
                TotpSecretProtected = totpProtected,
                TotpConfirmed = false,
                CreatedAt = now,
                UpdatedAt = now
            };

            db.AdminUsers.Add(entity);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            await _auditWriter.WriteAuditAsync(
                username,
                "AdminSetup",
                $"admin:{username}",
                "Initialisation du compte administrateur unique et génération du secret TOTP.",
                ipAddress,
                ct).ConfigureAwait(false);

            var otpUri = $"otpauth://totp/SENTINEL:{Uri.EscapeDataString(username)}?secret={base32Secret}&issuer=SENTINEL";
            _logger.LogInformation("Compte administrateur '{Username}' initialisé.", username);

            return AuthResult<SetupResponse>.Ok(new SetupResponse(base32Secret, otpUri));
        }
        finally
        {
            _setupGate.Release();
        }
    }

    public async Task<AuthResult<LoginResponse>> LoginAsync(LoginRequest request, string? ipAddress, CancellationToken ct = default)
    {
        if (request is null ||
            string.IsNullOrWhiteSpace(request.Username) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.TotpCode))
        {
            return AuthResult<LoginResponse>.Fail(AuthFailureKind.Unauthorized, "INVALID_CREDENTIALS", "Identifiants ou code TOTP manquants.");
        }

        var usernameInput = request.Username.Trim();
        var lockoutKey = $"{usernameInput.ToLowerInvariant()}|{ipAddress ?? "local"}";

        if (IsLockedOut(lockoutKey, out var retryUntil))
        {
            await _auditWriter.WriteAuditAsync(
                usernameInput,
                "AdminLoginLockedOut",
                $"admin:{usernameInput}",
                $"Tentative bloquée par verrouillage anti brute-force jusqu'à {retryUntil:O}.",
                ipAddress,
                ct).ConfigureAwait(false);

            return AuthResult<LoginResponse>.Fail(
                AuthFailureKind.LockedOut,
                "ACCOUNT_LOCKED",
                $"Compte temporairement verrouillé après {MaxFailedLoginAttempts} échecs consécutifs. Réessayez après {retryUntil:HH:mm:ss} UTC.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var admin = await db.AdminUsers
            .FirstOrDefaultAsync(u => u.Id == AdminUserEntity.SingletonId, ct)
            .ConfigureAwait(false);

        if (admin is null || !string.Equals(admin.Username, usernameInput, StringComparison.OrdinalIgnoreCase))
        {
            RecordFailedAttempt(lockoutKey);
            await _auditWriter.WriteAuditAsync(
                usernameInput,
                "AdminLoginFailed",
                $"admin:{usernameInput}",
                "Échec de connexion : compte inconnu ou non configuré.",
                ipAddress,
                ct).ConfigureAwait(false);

            return AuthResult<LoginResponse>.Fail(AuthFailureKind.Unauthorized, "INVALID_CREDENTIALS", "Identifiants invalides.");
        }

        if (!VerifyPassword(request.Password, admin.PasswordHash, admin.PasswordSalt))
        {
            var lockedNow = RecordFailedAttempt(lockoutKey);
            await _auditWriter.WriteAuditAsync(
                admin.Username,
                lockedNow ? "AdminLoginLockedOut" : "AdminLoginFailed",
                $"admin:{admin.Username}",
                lockedNow
                    ? $"Mot de passe incorrect — verrouillage activé pour {LockoutDuration.TotalMinutes:F0} min."
                    : "Échec de connexion : mot de passe incorrect.",
                ipAddress,
                ct).ConfigureAwait(false);

            return lockedNow
                ? AuthResult<LoginResponse>.Fail(AuthFailureKind.LockedOut, "ACCOUNT_LOCKED", $"Trop d'échecs consécutifs : compte verrouillé pour {LockoutDuration.TotalMinutes:F0} minutes.")
                : AuthResult<LoginResponse>.Fail(AuthFailureKind.Unauthorized, "INVALID_CREDENTIALS", "Identifiants invalides.");
        }

        if (!VerifyTotp(admin.TotpSecretProtected, request.TotpCode))
        {
            var lockedNow = RecordFailedAttempt(lockoutKey);
            await _auditWriter.WriteAuditAsync(
                admin.Username,
                lockedNow ? "AdminLoginLockedOut" : "AdminLoginFailed",
                $"admin:{admin.Username}",
                lockedNow
                    ? $"Code TOTP invalide — verrouillage activé pour {LockoutDuration.TotalMinutes:F0} min."
                    : "Échec de connexion : code TOTP invalide.",
                ipAddress,
                ct).ConfigureAwait(false);

            return lockedNow
                ? AuthResult<LoginResponse>.Fail(AuthFailureKind.LockedOut, "ACCOUNT_LOCKED", $"Trop d'échecs consécutifs : compte verrouillé pour {LockoutDuration.TotalMinutes:F0} minutes.")
                : AuthResult<LoginResponse>.Fail(AuthFailureKind.Unauthorized, "INVALID_TOTP", "Code TOTP invalide ou expiré.");
        }

        ClearFailedAttempts(lockoutKey);

        var now = DateTimeOffset.UtcNow;
        if (!admin.TotpConfirmed)
        {
            admin.TotpConfirmed = true;
            admin.UpdatedAt = now;
        }

        var ttlMinutes = Math.Clamp(_options.Value.SessionTtlMinutes, 5, 1440);
        var expiresAt = now.AddMinutes(ttlMinutes);
        var rawToken = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes));
        var tokenHash = HashChain.Sha256Hex(rawToken);

        db.AdminSessions.Add(new AdminSessionEntity
        {
            TokenHash = tokenHash,
            Username = admin.Username,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            IpAddress = ipAddress,
            Revoked = false
        });

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        await _auditWriter.WriteAuditAsync(
            admin.Username,
            "AdminLoginSuccess",
            $"admin:{admin.Username}",
            $"Session créée (expiration {expiresAt:O}).",
            ipAddress,
            ct).ConfigureAwait(false);

        return AuthResult<LoginResponse>.Ok(new LoginResponse(rawToken, expiresAt, admin.Username));
    }

    public async Task LogoutAsync(string tokenHash, string actor, string? ipAddress, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var session = await db.AdminSessions
            .FirstOrDefaultAsync(s => s.TokenHash == tokenHash, ct)
            .ConfigureAwait(false);

        if (session is not null && !session.Revoked)
        {
            session.Revoked = true;
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        await _auditWriter.WriteAuditAsync(
            actor,
            "AdminLogout",
            $"admin:{actor}",
            "Session administrateur révoquée.",
            ipAddress,
            ct).ConfigureAwait(false);
    }

    public async Task<AuthResult<bool>> ChangePasswordAsync(
        string currentTokenHash,
        ChangePasswordRequest request,
        string? ipAddress,
        CancellationToken ct = default)
    {
        if (request is null ||
            string.IsNullOrWhiteSpace(request.CurrentPassword) ||
            string.IsNullOrWhiteSpace(request.NewPassword) ||
            string.IsNullOrWhiteSpace(request.TotpCode))
        {
            return AuthResult<bool>.Fail(AuthFailureKind.BadRequest, "INVALID_INPUT", "Mot de passe actuel, nouveau mot de passe et code TOTP requis.");
        }

        if (request.NewPassword.Length < MinPasswordLength)
        {
            return AuthResult<bool>.Fail(AuthFailureKind.BadRequest, "WEAK_PASSWORD", $"Le nouveau mot de passe doit contenir au moins {MinPasswordLength} caractères.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var admin = await db.AdminUsers
            .FirstOrDefaultAsync(u => u.Id == AdminUserEntity.SingletonId, ct)
            .ConfigureAwait(false);

        if (admin is null)
        {
            return AuthResult<bool>.Fail(AuthFailureKind.Unauthorized, "NOT_CONFIGURED", "Compte administrateur non configuré.");
        }

        if (!VerifyPassword(request.CurrentPassword, admin.PasswordHash, admin.PasswordSalt))
        {
            await _auditWriter.WriteAuditAsync(
                admin.Username,
                "AdminPasswordChangeFailed",
                $"admin:{admin.Username}",
                "Échec de changement de mot de passe : mot de passe actuel incorrect.",
                ipAddress,
                ct).ConfigureAwait(false);

            return AuthResult<bool>.Fail(AuthFailureKind.Unauthorized, "INVALID_PASSWORD", "Mot de passe actuel incorrect.");
        }

        if (!VerifyTotp(admin.TotpSecretProtected, request.TotpCode))
        {
            await _auditWriter.WriteAuditAsync(
                admin.Username,
                "AdminPasswordChangeFailed",
                $"admin:{admin.Username}",
                "Échec de changement de mot de passe : code TOTP invalide.",
                ipAddress,
                ct).ConfigureAwait(false);

            return AuthResult<bool>.Fail(AuthFailureKind.Unauthorized, "INVALID_TOTP", "Code TOTP invalide.");
        }

        var (hash, salt) = HashPassword(request.NewPassword);
        admin.PasswordHash = hash;
        admin.PasswordSalt = salt;
        admin.UpdatedAt = DateTimeOffset.UtcNow;

        // Révoque les autres sessions actives par précaution
        var otherSessions = await db.AdminSessions
            .Where(s => !s.Revoked && s.TokenHash != currentTokenHash)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        foreach (var s in otherSessions)
        {
            s.Revoked = true;
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        await _auditWriter.WriteAuditAsync(
            admin.Username,
            "AdminPasswordChanged",
            $"admin:{admin.Username}",
            $"Mot de passe mis à jour ({otherSessions.Count} autre(s) session(s) révoquée(s)).",
            ipAddress,
            ct).ConfigureAwait(false);

        return AuthResult<bool>.Ok(true);
    }

    public async Task<AuthenticatedSession?> ValidateTokenAsync(string rawToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return null;

        var tokenHash = HashChain.Sha256Hex(rawToken);
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var session = await db.AdminSessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.TokenHash == tokenHash, ct)
            .ConfigureAwait(false);

        if (session is null || session.Revoked || session.ExpiresAt <= DateTimeOffset.UtcNow)
            return null;

        return new AuthenticatedSession(session.Username, session.TokenHash, session.ExpiresAt);
    }

    private static (string HashBase64, string SaltBase64) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            HashBytes);

        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    private static bool VerifyPassword(string password, string storedHashBase64, string storedSaltBase64)
    {
        try
        {
            var salt = Convert.FromBase64String(storedSaltBase64);
            var expected = Convert.FromBase64String(storedHashBase64);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                expected.Length);

            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyTotp(string protectedSecret, string totpCode)
    {
        try
        {
            var cleaned = totpCode.Trim().Replace(" ", "", StringComparison.Ordinal);
            if (cleaned.Length != 6)
                return false;

            var base32 = SecretProtector.UnprotectString(protectedSecret);
            var secretBytes = Base32Encoding.ToBytes(base32);
            var totp = new Totp(secretBytes, step: 30, mode: OtpHashMode.Sha1, totpSize: 6);
            return totp.VerifyTotp(cleaned, out _, new VerificationWindow(previous: 1, future: 1));
        }
        catch
        {
            return false;
        }
    }

    private bool IsLockedOut(string key, out DateTimeOffset until)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_lockoutGate)
        {
            if (_failedAttempts.TryGetValue(key, out var tracker) && tracker.LockedUntil is { } locked && locked > now)
            {
                until = locked;
                return true;
            }
            until = default;
            return false;
        }
    }

    private bool RecordFailedAttempt(string key)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_lockoutGate)
        {
            if (!_failedAttempts.TryGetValue(key, out var tracker))
            {
                tracker = new LoginAttemptTracker();
                _failedAttempts[key] = tracker;
            }

            if (tracker.LockedUntil is { } locked && locked <= now)
            {
                tracker.FailureCount = 0;
                tracker.LockedUntil = null;
            }

            if (now - tracker.WindowStart > LockoutDuration)
            {
                tracker.FailureCount = 0;
                tracker.WindowStart = now;
            }

            tracker.FailureCount++;
            if (tracker.FailureCount >= MaxFailedLoginAttempts)
            {
                tracker.LockedUntil = now + LockoutDuration;
                return true;
            }
            return false;
        }
    }

    private void ClearFailedAttempts(string key)
    {
        lock (_lockoutGate)
        {
            _failedAttempts.Remove(key);
        }
    }

    private sealed class LoginAttemptTracker
    {
        public int FailureCount { get; set; }
        public DateTimeOffset WindowStart { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? LockedUntil { get; set; }
    }
}
