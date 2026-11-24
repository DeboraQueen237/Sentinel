using Microsoft.ML.Data;

namespace Sentinel.ML;

/// <summary>
/// Indices fixes des 51 caractéristiques statiques PE inspirées d'EMBER.
/// L'ordre des indices correspond strictement à <see cref="PeFeatureExtractor.FeatureNames"/>.
/// </summary>
public static class PeFeatureIndex
{
    // --- En-tête & métadonnées générales (11) ---
    public const int LogFileSize = 0;
    public const int Is64Bit = 1;
    public const int IsDll = 2;
    public const int IsSigned = 3;
    public const int HasDebugInfo = 4;
    public const int HasResources = 5;
    public const int HasTls = 6;
    public const int HasRelocations = 7;
    public const int Subsystem = 8;
    public const int TimestampAnomaly = 9;
    public const int TimestampYearNorm = 10;

    // --- Sections PE (8) ---
    public const int SectionCount = 11;
    public const int ExecutableSectionCount = 12;
    public const int WritableExecutableSectionCount = 13;
    public const int MaxSectionEntropy = 14;
    public const int MeanSectionEntropy = 15;
    public const int MinSectionEntropy = 16;
    public const int VirtualToRawSizeRatio = 17;
    public const int HasPackerSectionName = 18;

    // --- Imports & Exports (8) ---
    public const int ImportDllCount = 19;
    public const int ImportFunctionCount = 20;
    public const int ExportCount = 21;
    public const int SuspiciousImportCount = 22;
    public const int CryptoApiCount = 23;
    public const int NetworkApiCount = 24;
    public const int InjectionApiCount = 25;
    public const int AntiDebugApiCount = 26;

    // --- Histogramme d'octets (16 bins) + statistiques globales (3) ---
    public const int ByteHistBinStart = 27;
    public const int ByteHistBinCount = 16;
    public const int GlobalByteEntropy = 43;
    public const int NullByteRatio = 44;
    public const int PrintableAsciiRatio = 45;

    // --- Statistiques de chaînes (aucun contenu stocké) (5) ---
    public const int PrintableStringCount = 46;
    public const int AvgStringLength = 47;
    public const int UrlLikeStringCount = 48;
    public const int PathLikeStringCount = 49;
    public const int RegistryStringCount = 50;

    public const int TotalCount = 51;
}

/// <summary>
/// Vecteur numérique fixe et immuable de 51 caractéristiques statiques d'un fichier PE.
/// Ne contient aucune donnée textuelle brute ni contenu sensible du fichier analysé.
/// </summary>
public sealed class PeFeatureVector
{
    public const int FeatureCount = PeFeatureIndex.TotalCount;

    private readonly float[] _values;

    public PeFeatureVector(float[] values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Length != FeatureCount)
        {
            throw new ArgumentException(
                $"Le vecteur de caractéristiques PE doit contenir exactement {FeatureCount} valeurs (reçu : {values.Length}).",
                nameof(values));
        }

        _values = new float[FeatureCount];
        for (var i = 0; i < FeatureCount; i++)
        {
            var v = values[i];
            _values[i] = float.IsFinite(v) ? v : 0f;
        }
    }

    /// <summary>Accès en lecture seule par indice.</summary>
    public float this[int index] => _values[index];

    /// <summary>Accès en lecture seule par nom de caractéristique.</summary>
    public float this[string featureName]
    {
        get
        {
            var idx = PeFeatureExtractor.IndexOf(featureName);
            if (idx < 0)
            {
                throw new KeyNotFoundException($"Caractéristique PE inconnue : '{featureName}'.");
            }
            return _values[idx];
        }
    }

    /// <summary>Vue en lecture seule sur les valeurs du vecteur.</summary>
    public ReadOnlySpan<float> AsSpan() => _values;

    /// <summary>Retourne une copie indépendante du tableau de flottants pour ML.NET.</summary>
    public float[] ToFloatArray()
    {
        var copy = new float[FeatureCount];
        Array.Copy(_values, copy, FeatureCount);
        return copy;
    }

    // Accesseurs typés pour les caractéristiques principales
    public float LogFileSize => _values[PeFeatureIndex.LogFileSize];
    public float Is64Bit => _values[PeFeatureIndex.Is64Bit];
    public float IsDll => _values[PeFeatureIndex.IsDll];
    public float IsSigned => _values[PeFeatureIndex.IsSigned];
    public float HasDebugInfo => _values[PeFeatureIndex.HasDebugInfo];
    public float HasResources => _values[PeFeatureIndex.HasResources];
    public float HasTls => _values[PeFeatureIndex.HasTls];
    public float HasRelocations => _values[PeFeatureIndex.HasRelocations];
    public float Subsystem => _values[PeFeatureIndex.Subsystem];
    public float TimestampAnomaly => _values[PeFeatureIndex.TimestampAnomaly];
    public float TimestampYearNorm => _values[PeFeatureIndex.TimestampYearNorm];

    public float SectionCount => _values[PeFeatureIndex.SectionCount];
    public float ExecutableSectionCount => _values[PeFeatureIndex.ExecutableSectionCount];
    public float WritableExecutableSectionCount => _values[PeFeatureIndex.WritableExecutableSectionCount];
    public float MaxSectionEntropy => _values[PeFeatureIndex.MaxSectionEntropy];
    public float MeanSectionEntropy => _values[PeFeatureIndex.MeanSectionEntropy];
    public float MinSectionEntropy => _values[PeFeatureIndex.MinSectionEntropy];
    public float VirtualToRawSizeRatio => _values[PeFeatureIndex.VirtualToRawSizeRatio];
    public float HasPackerSectionName => _values[PeFeatureIndex.HasPackerSectionName];

    public float ImportDllCount => _values[PeFeatureIndex.ImportDllCount];
    public float ImportFunctionCount => _values[PeFeatureIndex.ImportFunctionCount];
    public float ExportCount => _values[PeFeatureIndex.ExportCount];
    public float SuspiciousImportCount => _values[PeFeatureIndex.SuspiciousImportCount];
    public float CryptoApiCount => _values[PeFeatureIndex.CryptoApiCount];
    public float NetworkApiCount => _values[PeFeatureIndex.NetworkApiCount];
    public float InjectionApiCount => _values[PeFeatureIndex.InjectionApiCount];
    public float AntiDebugApiCount => _values[PeFeatureIndex.AntiDebugApiCount];

    public float GlobalByteEntropy => _values[PeFeatureIndex.GlobalByteEntropy];
    public float NullByteRatio => _values[PeFeatureIndex.NullByteRatio];
    public float PrintableAsciiRatio => _values[PeFeatureIndex.PrintableAsciiRatio];

    public float PrintableStringCount => _values[PeFeatureIndex.PrintableStringCount];
    public float AvgStringLength => _values[PeFeatureIndex.AvgStringLength];
    public float UrlLikeStringCount => _values[PeFeatureIndex.UrlLikeStringCount];
    public float PathLikeStringCount => _values[PeFeatureIndex.PathLikeStringCount];
    public float RegistryStringCount => _values[PeFeatureIndex.RegistryStringCount];

    /// <summary>Convertit ce vecteur en échantillon compatible ML.NET.</summary>
    public PeTrainingSample ToTrainingSample(bool label = false) => new()
    {
        Label = label,
        Features = ToFloatArray()
    };
}

/// <summary>
/// Échantillon d'entraînement ou d'inférence pour le pipeline ML.NET FastTree.
/// </summary>
public sealed class PeTrainingSample
{
    public bool Label { get; set; }

    [VectorType(PeFeatureVector.FeatureCount)]
    public float[] Features { get; set; } = new float[PeFeatureVector.FeatureCount];
}
