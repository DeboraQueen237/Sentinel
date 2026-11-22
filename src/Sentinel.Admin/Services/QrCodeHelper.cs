using System.Security.Cryptography;
using QRCoder;

namespace Sentinel.Admin.Services;

/// <summary>Génère localement l'image PNG Base64 du QR Code TOTP et calcule un code RFC 6238 à partir d'une clé Base32.</summary>
public static class QrCodeHelper
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string GeneratePngDataUri(string payload, int pixelsPerModule = 7)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(data);
        var bytes = qrCode.GetGraphic(pixelsPerModule);
        return $"data:image/png;base64,{Convert.ToBase64String(bytes)}";
    }

    /// <summary>Calcule le code TOTP RFC 6238 (6 chiffres, pas de 30 s, HMAC-SHA1) à partir d'une clé Base32.</summary>
    public static string ComputeTotpCode(string base32Secret, DateTimeOffset? utcNow = null)
    {
        if (string.IsNullOrWhiteSpace(base32Secret)) return string.Empty;
        var key = DecodeBase32(base32Secret);
        if (key.Length == 0) return string.Empty;

        var unixSeconds = (utcNow ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var counter = unixSeconds / 30;
        Span<byte> counterBytes = stackalloc byte[8];
        for (var i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        var hash = HMACSHA1.HashData(key, counterBytes);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | ((hash[offset + 1] & 0xFF) << 16)
                     | ((hash[offset + 2] & 0xFF) << 8)
                     | (hash[offset + 3] & 0xFF);
        var otp = binary % 1_000_000;
        return otp.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] DecodeBase32(string input)
    {
        var clean = input.Trim().TrimEnd('=').Replace(" ", "").Replace("-", "").ToUpperInvariant();
        if (clean.Length == 0) return Array.Empty<byte>();

        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bitsLeft = 0;
        foreach (var c in clean)
        {
            var val = Base32Alphabet.IndexOf(c);
            if (val < 0) return Array.Empty<byte>();
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return output.ToArray();
    }
}
