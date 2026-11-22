namespace Sentinel.ML;

/// <summary>
/// Paire train / test issue d'une séparation stratifiée reproductible.
/// </summary>
public sealed record StratifiedSplitResult(
    IReadOnlyList<PeTrainingSample> Train,
    IReadOnlyList<PeTrainingSample> Test);

/// <summary>
/// Générateur de jeu de données synthétique PE (bénin vs malveillant-like)
/// STRICTEMENT dédié aux tests unitaires et à la démonstration d'architecture SENTINEL v2.
/// Ne remplace en aucun cas un entraînement sur un corpus réel (ex. EMBER 2018).
/// </summary>
public static class SyntheticPeDatasetGenerator
{
    public const string DefaultDatasetNotice =
        "Jeu de données SYNTHÉTIQUE généré pour les tests unitaires et la démonstration d'architecture uniquement (non entraîné sur un corpus malveillant réel ; pour la production, entraîner sur EMBER 2018 hors dépôt).";

    /// <summary>
    /// Génère un jeu de données équilibré (50 % bénin-like, 50 % malveillant-like) avec graine fixe.
    /// Inclut plusieurs profils réalistes (système signé, utilitaire non signé, binaire .NET,
    /// installeur compressé, trojan packé, rançongiciel-like, loader/stealer-like) avec chevauchement contrôlé.
    /// </summary>
    public static IReadOnlyList<PeTrainingSample> Generate(int totalSamples = 4000, int seed = 42)
    {
        if (totalSamples < 20)
        {
            throw new ArgumentOutOfRangeException(nameof(totalSamples), "Au moins 20 échantillons sont requis.");
        }

        var rng = new Random(seed);
        var half = totalSamples / 2;
        var list = new List<PeTrainingSample>(totalSamples);

        for (var i = 0; i < half; i++)
        {
            list.Add(new PeTrainingSample
            {
                Label = false,
                Features = SampleBenignProfile(rng)
            });
        }

        for (var i = 0; i < totalSamples - half; i++)
        {
            list.Add(new PeTrainingSample
            {
                Label = true,
                Features = SampleMaliciousProfile(rng)
            });
        }

        // Mélange déterministe Fisher-Yates
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }

        return list;
    }

    /// <summary>Effectue une séparation train/test stratifiée déterministe (par défaut 80 % / 20 %).</summary>
    public static StratifiedSplitResult StratifiedSplit(
        IReadOnlyList<PeTrainingSample> samples,
        double testFraction = 0.2,
        int seed = 42)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (testFraction is <= 0.0 or >= 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(testFraction), "testFraction doit être dans ]0, 1[.");
        }

        var positives = samples.Where(s => s.Label).ToList();
        var negatives = samples.Where(s => !s.Label).ToList();

        var rng = new Random(seed);
        Shuffle(positives, rng);
        Shuffle(negatives, rng);

        var posTestCount = Math.Clamp((int)Math.Round(positives.Count * testFraction), 1, Math.Max(1, positives.Count - 1));
        var negTestCount = Math.Clamp((int)Math.Round(negatives.Count * testFraction), 1, Math.Max(1, negatives.Count - 1));

        var test = new List<PeTrainingSample>(posTestCount + negTestCount);
        var train = new List<PeTrainingSample>(samples.Count - test.Count);

        for (var i = 0; i < positives.Count; i++)
        {
            (i < posTestCount ? test : train).Add(positives[i]);
        }
        for (var i = 0; i < negatives.Count; i++)
        {
            (i < negTestCount ? test : train).Add(negatives[i]);
        }

        Shuffle(train, rng);
        Shuffle(test, rng);

        return new StratifiedSplitResult(train, test);
    }

    /// <summary>Crée un vecteur PE représentatif d'un binaire bénin signé classique.</summary>
    public static PeFeatureVector CreateBenignLikeVector(int seed = 101)
    {
        var rng = new Random(seed);
        return new PeFeatureVector(SampleSignedSystemBenign(rng));
    }

    /// <summary>Crée un vecteur PE représentatif d'un binaire suspect packé avec imports d'injection.</summary>
    public static PeFeatureVector CreateMaliciousLikeVector(int seed = 202)
    {
        var rng = new Random(seed);
        return new PeFeatureVector(SamplePackedInjectionMalicious(rng));
    }

    private static float[] SampleBenignProfile(Random rng)
    {
        var roll = rng.NextDouble();
        if (roll < 0.42) return SampleSignedSystemBenign(rng);
        if (roll < 0.68) return SampleDotNetBenign(rng);
        if (roll < 0.85) return SampleUnsignedDevToolBenign(rng);
        if (roll < 0.95) return SampleCompressedInstallerBenign(rng); // Haute entropie mais signé/ressources
        return SampleHardAdminToolBenign(rng); // Utilitaire système/diagnostic légitime (chevauchement réaliste)
    }

    private static float[] SampleMaliciousProfile(Random rng)
    {
        var roll = rng.NextDouble();
        if (roll < 0.36) return SamplePackedInjectionMalicious(rng);
        if (roll < 0.64) return SampleRansomwareLikeMalicious(rng);
        if (roll < 0.92) return SampleStealerDownloaderMalicious(rng);
        return SampleStealthyLoaderMalicious(rng); // Chargeur furtif à résolution dynamique (cas difficile)
    }

    private static float[] SampleSignedSystemBenign(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.4, 0.65), 3.8, 7.6);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.80 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.94 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.85 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.92 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.15 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.95 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.6 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.04 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = Clamp(NextGaussian(rng, 0.78, 0.12), 0.2, 1.0);

        f[PeFeatureIndex.SectionCount] = MathF.Round(Clamp(NextGaussian(rng, 5.5, 1.2), 3, 10));
        f[PeFeatureIndex.ExecutableSectionCount] = 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 6.15, 0.42), 4.5, 7.15);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(f[PeFeatureIndex.MaxSectionEntropy] - NextGaussian(rng, 1.35, 0.35), 2.0, 6.2);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 2.8, 0.9), 0.4, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.08, 0.15), 0.85, 2.2);
        f[PeFeatureIndex.HasPackerSectionName] = 0f;

        f[PeFeatureIndex.ImportDllCount] = MathF.Round(Clamp(NextGaussian(rng, 9.0, 4.0), 2, 25));
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 145.0, 75.0), 15, 500));
        f[PeFeatureIndex.ExportCount] = f[PeFeatureIndex.IsDll] > 0.5f
            ? MathF.Round(Clamp(NextGaussian(rng, 35.0, 30.0), 0, 200))
            : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.12 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.12 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.04 ? 1f : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.08 ? 1f : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] +
            (rng.NextDouble() < 0.25 ? rng.Next(1, 3) : 0f);

        PopulateByteHistogram(rng, f, uniformWeight: 0.25, nullRatioMean: 0.22, asciiRatioMean: 0.28, globalEntropyMean: 5.75);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 1200, 600), 80, 6000));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 13.5, 2.5), 6.0, 28.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.NextDouble() < 0.25 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 8, 6), 0, 40));
        f[PeFeatureIndex.RegistryStringCount] = rng.NextDouble() < 0.2 ? rng.Next(1, 4) : 0f;
        return f;
    }

    private static float[] SampleDotNetBenign(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 4.9, 0.55), 3.6, 6.8);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.50 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.75 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.78 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.85 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.90 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.5 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.15 ? 1f : 0f; // Builds déterministes .NET
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.80, 0.10), 0.3, 1.0);

        f[PeFeatureIndex.SectionCount] = rng.Next(3, 5);
        f[PeFeatureIndex.ExecutableSectionCount] = 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 5.75, 0.45), 4.0, 6.85);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 4.35, 0.55), 2.0, 5.8);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 2.1, 0.8), 0.2, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.05, 0.12), 0.9, 1.8);
        f[PeFeatureIndex.HasPackerSectionName] = 0f;

        f[PeFeatureIndex.ImportDllCount] = rng.Next(1, 3);
        f[PeFeatureIndex.ImportFunctionCount] = rng.Next(1, 8);
        f[PeFeatureIndex.ExportCount] = 0f;
        f[PeFeatureIndex.CryptoApiCount] = 0f;
        f[PeFeatureIndex.NetworkApiCount] = 0f;
        f[PeFeatureIndex.InjectionApiCount] = 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = 0f;
        f[PeFeatureIndex.SuspiciousImportCount] = 0f;

        PopulateByteHistogram(rng, f, uniformWeight: 0.20, nullRatioMean: 0.26, asciiRatioMean: 0.34, globalEntropyMean: 5.35);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 850, 450), 50, 4500));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 15.5, 3.0), 7.0, 32.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.NextDouble() < 0.2 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 5, 4), 0, 25));
        f[PeFeatureIndex.RegistryStringCount] = 0f;
        return f;
    }

    private static float[] SampleUnsignedDevToolBenign(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.2, 0.7), 4.0, 7.2);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.75 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.35 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.15 ? 1f : 0f; // Outil open-source non signé
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.60 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.15 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.90 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = 3f; // Console CUI
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.08 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = Clamp(NextGaussian(rng, 0.76, 0.15), 0.2, 1.0);

        f[PeFeatureIndex.SectionCount] = MathF.Round(Clamp(NextGaussian(rng, 6.0, 1.5), 4, 12));
        f[PeFeatureIndex.ExecutableSectionCount] = 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 6.35, 0.38), 5.0, 7.25);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 4.9, 0.5), 3.0, 6.3);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 2.6, 0.9), 0.4, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.12, 0.18), 0.85, 2.5);
        f[PeFeatureIndex.HasPackerSectionName] = 0f;

        f[PeFeatureIndex.ImportDllCount] = MathF.Round(Clamp(NextGaussian(rng, 7.5, 3.0), 2, 18));
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 110.0, 55.0), 20, 350));
        f[PeFeatureIndex.ExportCount] = rng.NextDouble() < 0.3 ? rng.Next(1, 25) : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.18 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.22 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.05 ? 1f : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.10 ? 1f : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] +
            (rng.NextDouble() < 0.3 ? rng.Next(1, 3) : 0f);

        PopulateByteHistogram(rng, f, uniformWeight: 0.30, nullRatioMean: 0.18, asciiRatioMean: 0.30, globalEntropyMean: 5.95);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 1400, 650), 120, 5500));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 14.0, 3.0), 6.5, 30.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.NextDouble() < 0.35 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 10, 7), 1, 45));
        f[PeFeatureIndex.RegistryStringCount] = rng.NextDouble() < 0.15 ? rng.Next(1, 3) : 0f;
        return f;
    }

    private static float[] SampleCompressedInstallerBenign(Random rng)
    {
        // Installeur légitime signé (ex. NSIS / Inno) : forte entropie, grande taille, mais signé et ressources présentes
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 6.7, 0.45), 5.8, 7.8);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.5 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.92 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.35 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = 1f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.1 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.85 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = 2f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.04 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = Clamp(NextGaussian(rng, 0.80, 0.10), 0.3, 1.0);

        f[PeFeatureIndex.SectionCount] = rng.Next(4, 7);
        f[PeFeatureIndex.ExecutableSectionCount] = 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 7.20, 0.32), 6.4, 7.82);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 5.4, 0.45), 4.0, 6.7);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 3.0, 0.8), 1.0, 5.0);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.15, 0.2), 0.9, 2.2);
        f[PeFeatureIndex.HasPackerSectionName] = 0f;

        f[PeFeatureIndex.ImportDllCount] = rng.Next(6, 14);
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 130, 45), 40, 280));
        f[PeFeatureIndex.ExportCount] = 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.15 ? 1f : 0f;
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.25 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] + rng.Next(1, 4);

        PopulateByteHistogram(rng, f, uniformWeight: 0.72, nullRatioMean: 0.05, asciiRatioMean: 0.24, globalEntropyMean: 7.35);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 1800, 700), 300, 6000));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 12.0, 2.5), 6.0, 24.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.Next(0, 4);
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 14, 6), 3, 45));
        f[PeFeatureIndex.RegistryStringCount] = rng.Next(1, 5);
        return f;
    }

    private static float[] SampleHardAdminToolBenign(Random rng)
    {
        // Utilitaire légitime d'administration/débogage (ex. outil diagnostic/UPX open-source) créant un chevauchement réaliste
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.1, 0.6), 4.0, 6.8);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.25 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.35 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.20 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.75 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.4 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.18 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.74, 0.18), 0.1, 1.0);

        f[PeFeatureIndex.SectionCount] = rng.Next(3, 8);
        f[PeFeatureIndex.ExecutableSectionCount] = rng.NextDouble() < 0.25 ? 2f : 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = rng.NextDouble() < 0.15 ? 1f : 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 6.95, 0.48), 5.6, 7.85);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 5.65, 0.60), 3.8, 7.2);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 3.2, 1.1), 0.6, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.55, 0.65), 0.9, 5.5);
        f[PeFeatureIndex.HasPackerSectionName] = rng.NextDouble() < 0.12 ? 1f : 0f;

        f[PeFeatureIndex.ImportDllCount] = rng.Next(4, 13);
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 85, 45), 15, 240));
        f[PeFeatureIndex.ExportCount] = rng.NextDouble() < 0.2 ? rng.Next(1, 12) : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.Next(0, 4);
        f[PeFeatureIndex.NetworkApiCount] = rng.Next(0, 5);
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.45 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.40 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] + rng.Next(1, 5);

        PopulateByteHistogram(rng, f, uniformWeight: 0.52, nullRatioMean: 0.11, asciiRatioMean: 0.27, globalEntropyMean: 6.65);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 680, 350), 60, 2600));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 12.2, 3.0), 6.0, 26.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.Next(0, 6);
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 16, 9), 1, 55));
        f[PeFeatureIndex.RegistryStringCount] = rng.Next(0, 6);
        return f;
    }

    private static float[] SampleStealthyLoaderMalicious(Random rng)
    {
        // Chargeur furtif non packé utilisant la résolution dynamique d'API (peu d'imports statiques suspects)
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.0, 0.6), 3.8, 6.7);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.60 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.22 ? 1f : 0f; // Certificat volé / auto-signé
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.30 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.25 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.75 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.55 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.30 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.72, 0.20), 0.1, 1.0);

        f[PeFeatureIndex.SectionCount] = rng.Next(4, 8);
        f[PeFeatureIndex.ExecutableSectionCount] = rng.NextDouble() < 0.30 ? 2f : 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = rng.NextDouble() < 0.25 ? 1f : 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 6.75, 0.45), 5.5, 7.65);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 5.45, 0.55), 3.8, 6.8);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 3.0, 1.0), 0.6, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 1.45, 0.55), 0.9, 4.5);
        f[PeFeatureIndex.HasPackerSectionName] = 0f;

        f[PeFeatureIndex.ImportDllCount] = rng.Next(3, 10);
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 65, 35), 10, 180));
        f[PeFeatureIndex.ExportCount] = rng.NextDouble() < 0.2 ? rng.Next(1, 8) : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.3 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.45 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.35 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.35 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] + rng.Next(0, 3);

        PopulateByteHistogram(rng, f, uniformWeight: 0.48, nullRatioMean: 0.12, asciiRatioMean: 0.27, globalEntropyMean: 6.55);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 520, 300), 50, 2000));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 11.8, 3.0), 5.5, 25.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.Next(0, 5);
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 15, 8), 1, 50));
        f[PeFeatureIndex.RegistryStringCount] = rng.Next(0, 6);
        return f;
    }

    private static float[] SamplePackedInjectionMalicious(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.1, 0.55), 3.9, 6.7);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.30 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.05 ? 1f : 0f; // Rarement signé (certificat volé/auto-signé)
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.08 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.42 ? 1f : 0f; // Callbacks TLS
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.7 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.55 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.55, 0.25), -0.3, 1.0);

        f[PeFeatureIndex.SectionCount] = MathF.Round(Clamp(NextGaussian(rng, 4.2, 1.3), 2, 9));
        f[PeFeatureIndex.ExecutableSectionCount] = rng.NextDouble() < 0.65 ? rng.Next(2, 4) : 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = rng.NextDouble() < 0.78 ? rng.Next(1, 3) : 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 7.68, 0.26), 6.8, 7.99);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 6.75, 0.45), 5.3, 7.95);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 5.1, 1.0), 1.5, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 3.8, 2.2), 1.2, 25.0);
        f[PeFeatureIndex.HasPackerSectionName] = rng.NextDouble() < 0.52 ? 1f : 0f;

        f[PeFeatureIndex.ImportDllCount] = MathF.Round(Clamp(NextGaussian(rng, 3.5, 1.8), 1, 10));
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 36, 22), 4, 140));
        f[PeFeatureIndex.ExportCount] = rng.NextDouble() < 0.12 ? rng.Next(1, 6) : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.35 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.55 ? rng.Next(1, 6) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = MathF.Round(Clamp(NextGaussian(rng, 4.2, 1.8), 1, 11));
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.65 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] + rng.Next(2, 6);

        PopulateByteHistogram(rng, f, uniformWeight: 0.85, nullRatioMean: 0.03, asciiRatioMean: 0.22, globalEntropyMean: 7.58);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 220, 140), 15, 1200));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 8.8, 2.2), 5.0, 20.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.NextDouble() < 0.5 ? rng.Next(1, 8) : 0f;
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 12, 8), 0, 50));
        f[PeFeatureIndex.RegistryStringCount] = rng.NextDouble() < 0.55 ? rng.Next(1, 7) : 0f;
        return f;
    }

    private static float[] SampleRansomwareLikeMalicious(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 5.3, 0.5), 4.2, 6.8);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.55 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.15 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.04 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.10 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.60 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.30 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.65 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.6 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.72, 0.2), 0.0, 1.0);

        f[PeFeatureIndex.SectionCount] = MathF.Round(Clamp(NextGaussian(rng, 5.2, 1.4), 3, 10));
        f[PeFeatureIndex.ExecutableSectionCount] = rng.NextDouble() < 0.45 ? 2f : 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = rng.NextDouble() < 0.45 ? 1f : 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 7.35, 0.35), 6.4, 7.98);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 6.25, 0.48), 4.8, 7.6);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 4.1, 1.0), 1.0, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 2.2, 1.1), 1.0, 14.0);
        f[PeFeatureIndex.HasPackerSectionName] = rng.NextDouble() < 0.30 ? 1f : 0f;

        f[PeFeatureIndex.ImportDllCount] = MathF.Round(Clamp(NextGaussian(rng, 5.5, 2.2), 2, 14));
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 72, 32), 15, 200));
        f[PeFeatureIndex.ExportCount] = 0f;
        f[PeFeatureIndex.CryptoApiCount] = MathF.Round(Clamp(NextGaussian(rng, 5.5, 2.0), 2, 12));
        f[PeFeatureIndex.NetworkApiCount] = rng.NextDouble() < 0.35 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.5 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = rng.NextDouble() < 0.55 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] + rng.Next(2, 7);

        PopulateByteHistogram(rng, f, uniformWeight: 0.68, nullRatioMean: 0.06, asciiRatioMean: 0.25, globalEntropyMean: 7.22);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 520, 260), 40, 2200));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 11.2, 2.8), 5.5, 24.0);
        f[PeFeatureIndex.UrlLikeStringCount] = rng.NextDouble() < 0.45 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 28, 12), 4, 90));
        f[PeFeatureIndex.RegistryStringCount] = MathF.Round(Clamp(NextGaussian(rng, 5, 3), 1, 18));
        return f;
    }

    private static float[] SampleStealerDownloaderMalicious(Random rng)
    {
        var f = new float[PeFeatureVector.FeatureCount];
        f[PeFeatureIndex.LogFileSize] = Clamp(NextGaussian(rng, 4.75, 0.55), 3.6, 6.4);
        f[PeFeatureIndex.Is64Bit] = rng.NextDouble() < 0.40 ? 1f : 0f;
        f[PeFeatureIndex.IsDll] = rng.NextDouble() < 0.25 ? 1f : 0f;
        f[PeFeatureIndex.IsSigned] = rng.NextDouble() < 0.03 ? 1f : 0f;
        f[PeFeatureIndex.HasDebugInfo] = rng.NextDouble() < 0.12 ? 1f : 0f;
        f[PeFeatureIndex.HasResources] = rng.NextDouble() < 0.50 ? 1f : 0f;
        f[PeFeatureIndex.HasTls] = rng.NextDouble() < 0.25 ? 1f : 0f;
        f[PeFeatureIndex.HasRelocations] = rng.NextDouble() < 0.60 ? 1f : 0f;
        f[PeFeatureIndex.Subsystem] = rng.NextDouble() < 0.65 ? 2f : 3f;
        f[PeFeatureIndex.TimestampAnomaly] = rng.NextDouble() < 0.48 ? 1f : 0f;
        f[PeFeatureIndex.TimestampYearNorm] = f[PeFeatureIndex.TimestampAnomaly] > 0.5f
            ? 0f
            : Clamp(NextGaussian(rng, 0.65, 0.22), -0.2, 1.0);

        f[PeFeatureIndex.SectionCount] = MathF.Round(Clamp(NextGaussian(rng, 4.8, 1.3), 2, 9));
        f[PeFeatureIndex.ExecutableSectionCount] = rng.NextDouble() < 0.40 ? 2f : 1f;
        f[PeFeatureIndex.WritableExecutableSectionCount] = rng.NextDouble() < 0.50 ? 1f : 0f;
        f[PeFeatureIndex.MaxSectionEntropy] = Clamp(NextGaussian(rng, 7.12, 0.45), 5.9, 7.95);
        f[PeFeatureIndex.MeanSectionEntropy] = Clamp(NextGaussian(rng, 5.95, 0.55), 4.2, 7.4);
        f[PeFeatureIndex.MinSectionEntropy] = Clamp(NextGaussian(rng, 3.8, 1.1), 0.8, f[PeFeatureIndex.MeanSectionEntropy]);
        f[PeFeatureIndex.VirtualToRawSizeRatio] = Clamp(NextGaussian(rng, 2.0, 0.9), 0.95, 12.0);
        f[PeFeatureIndex.HasPackerSectionName] = rng.NextDouble() < 0.25 ? 1f : 0f;

        f[PeFeatureIndex.ImportDllCount] = MathF.Round(Clamp(NextGaussian(rng, 5.0, 2.0), 2, 12));
        f[PeFeatureIndex.ImportFunctionCount] = MathF.Round(Clamp(NextGaussian(rng, 64, 30), 12, 180));
        f[PeFeatureIndex.ExportCount] = rng.NextDouble() < 0.1 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.CryptoApiCount] = rng.NextDouble() < 0.55 ? rng.Next(1, 4) : 0f;
        f[PeFeatureIndex.NetworkApiCount] = MathF.Round(Clamp(NextGaussian(rng, 5.8, 2.2), 2, 14));
        f[PeFeatureIndex.InjectionApiCount] = rng.NextDouble() < 0.65 ? rng.Next(1, 5) : 0f;
        f[PeFeatureIndex.AntiDebugApiCount] = MathF.Round(Clamp(NextGaussian(rng, 2.5, 1.3), 0, 7));
        f[PeFeatureIndex.SuspiciousImportCount] =
            f[PeFeatureIndex.CryptoApiCount] + f[PeFeatureIndex.NetworkApiCount] +
            f[PeFeatureIndex.InjectionApiCount] + f[PeFeatureIndex.AntiDebugApiCount] + rng.Next(2, 6);

        PopulateByteHistogram(rng, f, uniformWeight: 0.58, nullRatioMean: 0.08, asciiRatioMean: 0.29, globalEntropyMean: 6.90);

        f[PeFeatureIndex.PrintableStringCount] = MathF.Round(Clamp(NextGaussian(rng, 450, 220), 40, 2000));
        f[PeFeatureIndex.AvgStringLength] = Clamp(NextGaussian(rng, 12.8, 3.2), 6.0, 28.0);
        f[PeFeatureIndex.UrlLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 7.5, 3.5), 2, 25));
        f[PeFeatureIndex.PathLikeStringCount] = MathF.Round(Clamp(NextGaussian(rng, 22, 10), 3, 75));
        f[PeFeatureIndex.RegistryStringCount] = MathF.Round(Clamp(NextGaussian(rng, 6, 3), 1, 20));
        return f;
    }

    private static void PopulateByteHistogram(
        Random rng,
        float[] f,
        double uniformWeight,
        double nullRatioMean,
        double asciiRatioMean,
        double globalEntropyMean)
    {
        Span<double> bins = stackalloc double[PeFeatureIndex.ByteHistBinCount];
        double sum = 0.0;
        for (var b = 0; b < PeFeatureIndex.ByteHistBinCount; b++)
        {
            double baseWeight = b switch
            {
                0 => 1.0 + (1.0 - uniformWeight) * 3.5,                  // 0x00..0x0F (octets nuls/padding)
                2 or 3 or 4 or 5 or 6 or 7 => 1.0 + (1.0 - uniformWeight) * 1.4, // ASCII imprimable
                15 => 1.0 + (1.0 - uniformWeight) * 1.1,                 // 0xF0..0xFF (opcodes / sign-ext)
                _ => 1.0
            };

            var noisy = Math.Max(0.05, baseWeight + NextGaussian(rng, 0.0, 0.18));
            bins[b] = noisy;
            sum += noisy;
        }

        for (var b = 0; b < PeFeatureIndex.ByteHistBinCount; b++)
        {
            f[PeFeatureIndex.ByteHistBinStart + b] = (float)(bins[b] / sum);
        }

        f[PeFeatureIndex.GlobalByteEntropy] = Clamp(NextGaussian(rng, globalEntropyMean, 0.35), 2.5, 7.99);
        f[PeFeatureIndex.NullByteRatio] = Clamp(NextGaussian(rng, nullRatioMean, 0.05), 0.002, 0.65);
        f[PeFeatureIndex.PrintableAsciiRatio] = Clamp(NextGaussian(rng, asciiRatioMean, 0.06), 0.05, 0.75);
    }

    private static double NextGaussian(Random rng, double mean, double stdDev)
    {
        var u1 = Math.Max(1e-12, 1.0 - rng.NextDouble());
        var u2 = 1.0 - rng.NextDouble();
        var z = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Cos(2.0 * Math.PI * u2);
        return mean + z * stdDev;
    }

    private static float Clamp(double value, double min, double max) =>
        (float)Math.Clamp(value, min, max);

    private static void Shuffle<T>(IList<T> items, Random rng)
    {
        for (var i = items.Count - 1; i > 0; i--)
        {
            var j = rng.Next(i + 1);
            (items[i], items[j]) = (items[j], items[i]);
        }
    }
}
