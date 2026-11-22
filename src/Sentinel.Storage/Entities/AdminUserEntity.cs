namespace Sentinel.Storage.Entities;

/// <summary>Compte administrateur unique (Id = 1) avec hachage PBKDF2 et secret TOTP protégé par DPAPI (doc §10.2).</summary>
public sealed class AdminUserEntity
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    public string Username { get; set; } = string.Empty;

    /// <summary>Empreinte PBKDF2 du mot de passe (encodée Base64).</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Sel cryptographique aléatoire (encodé Base64).</summary>
    public string PasswordSalt { get; set; } = string.Empty;

    /// <summary>Secret TOTP Base32 chiffré au repos via <c>SecretProtector</c> (DPAPI).</summary>
    public string TotpSecretProtected { get; set; } = string.Empty;

    /// <summary>Devient vrai dès la première connexion TOTP validée.</summary>
    public bool TotpConfirmed { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
