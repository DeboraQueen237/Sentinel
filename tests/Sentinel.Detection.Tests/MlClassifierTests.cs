using System.Globalization;
using System.Text.Json;
using FluentAssertions;
using Sentinel.ML;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Detection.Tests;

public sealed class MlClassifierTests
{
    [Fact]
    public void PeFeatureExtractor_ExtractsValidVector_FromRealPeAssembly()
    {
        var assemblyPath = typeof(SecurityEvent).Assembly.Location;
        File.Exists(assemblyPath).Should().BeTrue("l'assembly Sentinel.Shared.dll doit exister sur disque");

        var extractor = new PeFeatureExtractor();
        var ok = extractor.TryExtract(assemblyPath, out var vector, out var error);

        ok.Should().BeTrue(error);
        vector.Should().NotBeNull();
        PeFeatureExtractor.FeatureNames.Should().HaveCount(PeFeatureVector.FeatureCount);

        var raw = vector!.ToFloatArray();
        raw.Should().HaveCount(PeFeatureVector.FeatureCount);
        raw.Should().OnlyContain(v => float.IsFinite(v));

        vector.LogFileSize.Should().BeGreaterThan(3.0f);
        vector.IsDll.Should().Be(1f);
        vector.SectionCount.Should().BeGreaterThanOrEqualTo(1f);
        vector.MaxSectionEntropy.Should().BeInRange(0.1f, 8.0f);
        vector.GlobalByteEntropy.Should().BeInRange(0.1f, 8.0f);
        vector.NullByteRatio.Should().BeInRange(0f, 1f);
        vector.PrintableAsciiRatio.Should().BeInRange(0f, 1f);
        vector.PrintableStringCount.Should().BeGreaterThan(10f);
        vector.AvgStringLength.Should().BeGreaterThanOrEqualTo(5f);

        // L'histogramme d'octets sur 16 bins doit sommer à ~1.0
        var histSum = 0f;
        for (var i = 0; i < PeFeatureIndex.ByteHistBinCount; i++)
        {
            var bin = vector[PeFeatureIndex.ByteHistBinStart + i];
            bin.Should().BeInRange(0f, 1f);
            histSum += bin;
        }
        histSum.Should().BeApproximately(1.0f, 0.01f);

        // Garantit l'absence de tout contenu textuel brut stocké dans PeFeatureVector
        var stringProps = typeof(PeFeatureVector)
            .GetProperties()
            .Where(p => p.PropertyType == typeof(string) || p.PropertyType == typeof(IReadOnlyList<string>))
            .ToList();
        stringProps.Should().BeEmpty("aucune chaîne brute extraite du binaire ne doit être stockée dans le vecteur");
    }

    [Fact]
    public void PeFeatureExtractor_HandlesMissingAndNonPeFiles_Gracefully()
    {
        var extractor = new PeFeatureExtractor();

        extractor.TryExtract(@"C:\nonexistent-path-sentinel-ml-test.exe", out var missingVec, out var missingErr)
            .Should().BeFalse();
        missingVec.Should().BeNull();
        missingErr.Should().NotBeNullOrWhiteSpace();

        var tempFile = Path.Combine(Path.GetTempPath(), $"sentinel-nonpe-{Guid.NewGuid():N}.txt");
        try
        {
            File.WriteAllText(tempFile, "Ceci n'est absolument pas un binaire Portable Executable Windows.");
            extractor.TryExtract(tempFile, out var nonPeVec, out var nonPeErr).Should().BeFalse();
            nonPeVec.Should().BeNull();
            nonPeErr.Should().NotBeNullOrWhiteSpace();
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void SyntheticPeDatasetGenerator_ProducesDeterministicBalancedStratifiedSplit()
    {
        var dataset1 = SyntheticPeDatasetGenerator.Generate(totalSamples: 1000, seed: 42);
        var dataset2 = SyntheticPeDatasetGenerator.Generate(totalSamples: 1000, seed: 42);

        dataset1.Should().HaveCount(1000);
        dataset1.Count(s => s.Label).Should().Be(500);
        dataset1.Count(s => !s.Label).Should().Be(500);

        // Reproductibilité exacte avec la même graine
        for (var i = 0; i < 25; i++)
        {
            dataset1[i].Label.Should().Be(dataset2[i].Label);
            dataset1[i].Features.Should().Equal(dataset2[i].Features);
        }

        var split = SyntheticPeDatasetGenerator.StratifiedSplit(dataset1, testFraction: 0.2, seed: 42);
        split.Train.Should().HaveCount(800);
        split.Test.Should().HaveCount(200);
        split.Test.Count(s => s.Label).Should().Be(100);
        split.Test.Count(s => !s.Label).Should().Be(100);

        // Différences statistiques attendues entre profils bénin-like et malveillant-like
        var benignMeanEntropy = dataset1.Where(s => !s.Label).Average(s => s.Features[PeFeatureIndex.MaxSectionEntropy]);
        var malMeanEntropy = dataset1.Where(s => s.Label).Average(s => s.Features[PeFeatureIndex.MaxSectionEntropy]);
        malMeanEntropy.Should().BeGreaterThan(benignMeanEntropy);

        var benignSignedRate = dataset1.Where(s => !s.Label).Average(s => s.Features[PeFeatureIndex.IsSigned]);
        var malSignedRate = dataset1.Where(s => s.Label).Average(s => s.Features[PeFeatureIndex.IsSigned]);
        benignSignedRate.Should().BeGreaterThan(malSignedRate);
    }

    [Fact]
    public void PeClassifierTrainer_TrainsFastTree_SavesAndReloadsZip_WithValidMetricsAndExplainability()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-ml-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var modelPath = Path.Combine(tempDir, "pe-classifier.zip");
            var metaPath = Path.Combine(tempDir, "pe-classifier.meta.json");

            var samples = SyntheticPeDatasetGenerator.Generate(totalSamples: 2500, seed: 42);
            var trainer = new PeClassifierTrainer();
            var options = new MlTrainingOptions
            {
                Version = "2.0.0-test",
                Seed = 42,
                NumberOfTrees = 80,
                NumberOfLeaves = 24,
                TestFraction = 0.2
            };

            var trainingResult = trainer.TrainAndEvaluate(samples, options, modelPath, metaPath);
            var eval = trainingResult.Evaluation;

            File.Exists(modelPath).Should().BeTrue();
            File.Exists(metaPath).Should().BeTrue();

            eval.Auc.Should().BeGreaterThan(0.95);
            eval.RecallAt01Fpr.Should().BeGreaterThan(0.50);
            eval.EffectiveFpr.Should().BeLessThanOrEqualTo(0.001 + 1e-9);
            eval.F1Score.Should().BeGreaterThan(0.90);
            eval.Precision.Should().BeGreaterThan(0.90);
            eval.CalibratedThreshold.Should().BeInRange(0.0, 1.0);
            eval.TopGlobalFeatures.Should().NotBeEmpty();

            // Vérification des métadonnées persistées en JSON
            var metaJson = File.ReadAllText(metaPath);
            var loadedMeta = JsonSerializer.Deserialize<MlModelMetadata>(metaJson, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            loadedMeta.Should().NotBeNull();
            loadedMeta!.Version.Should().Be("2.0.0-test");
            loadedMeta.FeatureCount.Should().Be(PeFeatureVector.FeatureCount);
            loadedMeta.DatasetNotice.Should().Contain("SYNTHÉTIQUE");

            // Rechargement dans le service d'inférence
            using var classifier = new PeMlClassifierService(modelPath, metaPath, new MlSettings());
            var status = classifier.GetStatus();
            status.Loaded.Should().BeTrue();
            status.Version.Should().Be("2.0.0-test");
            status.FeatureCount.Should().Be(PeFeatureVector.FeatureCount);
            status.Auc.Should().BeApproximately(eval.Auc, 1e-6);
            status.RecallAt01Fpr.Should().BeApproximately(eval.RecallAt01Fpr, 1e-6);

            // Prédictions bénin-like vs malveillant-like avec caractéristiques explicatives
            var benignVec = SyntheticPeDatasetGenerator.CreateBenignLikeVector(seed: 101);
            var maliciousVec = SyntheticPeDatasetGenerator.CreateMaliciousLikeVector(seed: 202);

            var benignPred = classifier.PredictFeatures(benignVec);
            var maliciousPred = classifier.PredictFeatures(maliciousVec);

            benignPred.ModelLoaded.Should().BeTrue();
            maliciousPred.ModelLoaded.Should().BeTrue();
            maliciousPred.MaliciousProbability.Should().BeGreaterThan(0.75);
            benignPred.MaliciousProbability.Should().BeLessThan(0.35);
            maliciousPred.MaliciousProbability.Should().BeGreaterThan(benignPred.MaliciousProbability);

            maliciousPred.TopContributingFeatures.Count.Should().BeInRange(3, 5);
            foreach (var factor in maliciousPred.TopContributingFeatures)
            {
                factor.Should().Contain("=");
                var featName = factor.Split('=')[0];
                PeFeatureExtractor.FeatureNames.Should().Contain(featName);
            }

            // Prédiction bout-en-bout sur un vrai binaire PE (.NET assembly)
            var realAssemblyPath = typeof(SecurityEvent).Assembly.Location;
            var realPred = classifier.PredictFile(realAssemblyPath);
            realPred.ModelLoaded.Should().BeTrue();
            realPred.ModelVersion.Should().Be("2.0.0-test");
            realPred.MaliciousProbability.Should().BeInRange(0.0, 1.0);
            realPred.TopContributingFeatures.Should().NotBeEmpty();
            realPred.BoundedScoreContribution.Should().BeLessThanOrEqualTo(new MlSettings().MaxScoreContribution);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void PeMlClassifierService_StrictlyCapsScoreContribution_AndIsNeverSolelyDecisive()
    {
        var defaultSettings = new MlSettings(); // MaxScoreContribution = 35
        var moderateThreshold = ThreatLevels.Default.Moderate; // 55

        // Même à probabilité 1.0, le score ML ne dépasse jamais MaxScoreContribution et reste sous Moderate (55)
        var maxDefault = PeMlClassifierService.ComputeBoundedScoreContribution(1.0, defaultSettings);
        maxDefault.Should().BeLessThanOrEqualTo(defaultSettings.MaxScoreContribution);
        maxDefault.Should().BeLessThan(moderateThreshold);
        ((int)ThreatLevels.FromScore(maxDefault)).Should().BeLessThan((int)ThreatLevel.Moderate);

        // Plafond personnalisé plus bas respecté strictement
        var customSettings = new MlSettings { MaxScoreContribution = 20 };
        PeMlClassifierService.ComputeBoundedScoreContribution(1.0, customSettings).Should().Be(20);

        // Même en cas de configuration excessive (100), le plafond absolu empêche le ML d'être seul décisif
        var excessiveSettings = new MlSettings { MaxScoreContribution = 100 };
        var capped = PeMlClassifierService.ComputeBoundedScoreContribution(1.0, excessiveSettings);
        capped.Should().BeLessThanOrEqualTo(PeMlClassifierService.AbsoluteSafetyScoreCeiling);
        capped.Should().BeLessThan(moderateThreshold);
        ((int)ThreatLevels.FromScore(capped)).Should().BeLessThan((int)ThreatLevel.Moderate);

        // Désactivation explicite -> 0
        var disabledSettings = new MlSettings { Enabled = false };
        PeMlClassifierService.ComputeBoundedScoreContribution(0.99, disabledSettings).Should().Be(0);

        // Probabilité très faible -> 0 (pas de bruit sur les binaires clairement bénins)
        PeMlClassifierService.ComputeBoundedScoreContribution(0.05, defaultSettings).Should().Be(0);
    }

    [Fact]
    public void PeMlClassifierService_ReturnsUnloadedWhenModelMissing_AndSupportsConcurrentPredictions()
    {
        var missingPath = Path.Combine(Path.GetTempPath(), $"missing-model-{Guid.NewGuid():N}.zip");
        using (var unloaded = new PeMlClassifierService(missingPath))
        {
            unloaded.GetStatus().Loaded.Should().BeFalse();
            var res = unloaded.PredictFeatures(SyntheticPeDatasetGenerator.CreateMaliciousLikeVector());
            res.ModelLoaded.Should().BeFalse();
            res.BoundedScoreContribution.Should().Be(0);
            res.MaliciousProbability.Should().Be(0.0);
        }

        // Vérification thread-safety sur modèle chargé
        var tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-ml-mt-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var modelPath = Path.Combine(tempDir, "pe-classifier.zip");
            var samples = SyntheticPeDatasetGenerator.Generate(totalSamples: 800, seed: 7);
            new PeClassifierTrainer().TrainAndEvaluate(
                samples,
                new MlTrainingOptions { NumberOfTrees = 30, NumberOfLeaves = 16, Seed = 7 },
                modelPath);

            using var classifier = new PeMlClassifierService(modelPath);
            var target = SyntheticPeDatasetGenerator.CreateMaliciousLikeVector(seed: 303);
            var results = new MlPredictionResult[24];

            Parallel.For(0, results.Length, i =>
            {
                results[i] = classifier.PredictFeatures(target);
            });

            var expectedProb = results[0].MaliciousProbability;
            results.Should().OnlyContain(r =>
                r.ModelLoaded &&
                Math.Abs(r.MaliciousProbability - expectedProb) < 1e-6 &&
                r.BoundedScoreContribution <= 35);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void PeDatasetLoader_LoadsCsvAndEmberJsonl_AndSkipsUnlabeledRows()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-ml-loader-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1) CSV avec en-tête nommé et ligne non étiquetée (-1)
            var csvPath = Path.Combine(tempDir, "sample.csv");
            var header = "Label," + string.Join(",", PeFeatureExtractor.FeatureNames);
            var rowBenign = "0," + string.Join(",", Enumerable.Range(0, PeFeatureVector.FeatureCount).Select(i => (i * 0.1f).ToString("0.0", CultureInfo.InvariantCulture)));
            var rowUnlabeled = "-1," + string.Join(",", Enumerable.Repeat("0", PeFeatureVector.FeatureCount));
            var rowMalicious = "1," + string.Join(",", Enumerable.Repeat("1.5", PeFeatureVector.FeatureCount));
            File.WriteAllLines(csvPath, ["# commentaire", header, rowBenign, rowUnlabeled, rowMalicious]);

            var csvSamples = PeDatasetLoader.LoadFromCsv(csvPath);
            csvSamples.Should().HaveCount(2);
            csvSamples[0].Label.Should().BeFalse();
            csvSamples[1].Label.Should().BeTrue();
            csvSamples[1].Features.Should().HaveCount(PeFeatureVector.FeatureCount);
            csvSamples[1].Features[0].Should().BeApproximately(1.5f, 1e-5f);

            // 2) JSONL au format EMBER 2018 natif (avec une entrée label=-1 ignorée)
            var jsonlPath = Path.Combine(tempDir, "ember.jsonl");
            var histJson = "[" + string.Join(",", Enumerable.Repeat("10", 256)) + "]";
            var emberUnlabeled = """{"sha256":"aaa","label":-1,"general":{"size":10000}}""";
            var emberMalicious = $$$"""
                {"sha256":"bbb","label":1,"general":{"size":262144,"has_debug":0,"has_relocations":1,"has_resources":1,"has_signature":0,"has_tls":1,"exports":0,"imports":3},"header":{"coff":{"timestamp":0,"machine":"AMD64","characteristics":["EXECUTABLE_IMAGE"]},"optional":{"subsystem":"WINDOWS_GUI","magic":"PE32+"}},"section":{"sections":[{"name":"UPX0","size":4096,"vsize":32768,"entropy":7.85,"props":["MEM_EXECUTE","MEM_WRITE"]}]},"imports":{"KERNEL32.dll":["VirtualAllocEx","WriteProcessMemory","IsDebuggerPresent"]},"exports":[],"histogram":{{{histJson}}},"strings":{"numstrings":120,"avlength":9.5,"urls":4,"paths":11,"registry":3}}
                """;
            File.WriteAllLines(jsonlPath, [emberUnlabeled, emberMalicious]);

            var emberSamples = PeDatasetLoader.LoadFromEmberJsonl(jsonlPath);
            emberSamples.Should().HaveCount(1);
            var s = emberSamples[0];
            s.Label.Should().BeTrue();
            s.Features[PeFeatureIndex.Is64Bit].Should().Be(1f);
            s.Features[PeFeatureIndex.IsSigned].Should().Be(0f);
            s.Features[PeFeatureIndex.HasTls].Should().Be(1f);
            s.Features[PeFeatureIndex.TimestampAnomaly].Should().Be(1f);
            s.Features[PeFeatureIndex.WritableExecutableSectionCount].Should().Be(1f);
            s.Features[PeFeatureIndex.HasPackerSectionName].Should().Be(1f);
            s.Features[PeFeatureIndex.MaxSectionEntropy].Should().BeApproximately(7.85f, 0.01f);
            s.Features[PeFeatureIndex.InjectionApiCount].Should().Be(2f);
            s.Features[PeFeatureIndex.AntiDebugApiCount].Should().Be(1f);
            s.Features[PeFeatureIndex.GlobalByteEntropy].Should().BeApproximately(8.0f, 0.01f);
            s.Features[PeFeatureIndex.UrlLikeStringCount].Should().Be(4f);
            s.Features[PeFeatureIndex.RegistryStringCount].Should().Be(3f);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
