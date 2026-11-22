using System.Text.Json;
using Microsoft.ML;
using Microsoft.ML.Calibrators;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.FastTree;

namespace Sentinel.ML;

/// <summary>
/// Entraîneur et évaluateur du classifieur binaire PE basé sur ML.NET <see cref="FastTreeBinaryTrainer"/>.
/// Calcule ROC-AUC, Recall @ 0,1 % FPR, F1, Précision, FPR effectif et seuil calibré,
/// puis persiste le modèle versionné (<c>.zip</c>) et ses métadonnées (<c>.meta.json</c>).
/// </summary>
public sealed class PeClassifierTrainer
{
    public const string AlgorithmName = "ML.NET FastTreeBinaryTrainer (GBDT + Platt calibration)";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Entraîne, évalue et sauvegarde optionnellement un modèle FastTree à partir d'un jeu d'échantillons.
    /// </summary>
    public MlTrainingResult TrainAndEvaluate(
        IReadOnlyList<PeTrainingSample> samples,
        MlTrainingOptions? options = null,
        string? outputModelPath = null,
        string? outputMetadataPath = null)
    {
        ArgumentNullException.ThrowIfNull(samples);
        options ??= new MlTrainingOptions();

        if (samples.Count < 20)
        {
            throw new ArgumentException("Au moins 20 échantillons étiquetés sont nécessaires pour l'entraînement.", nameof(samples));
        }

        var split = SyntheticPeDatasetGenerator.StratifiedSplit(samples, options.TestFraction, options.Seed);
        return TrainAndEvaluate(split.Train, split.Test, options, outputModelPath, outputMetadataPath);
    }

    /// <summary>
    /// Entraîne un modèle FastTree sur <paramref name="trainSamples"/>, l'évalue sur <paramref name="testSamples"/>
    /// et persiste le modèle + métadonnées si <paramref name="outputModelPath"/> est renseigné.
    /// </summary>
    public MlTrainingResult TrainAndEvaluate(
        IReadOnlyList<PeTrainingSample> trainSamples,
        IReadOnlyList<PeTrainingSample> testSamples,
        MlTrainingOptions? options = null,
        string? outputModelPath = null,
        string? outputMetadataPath = null)
    {
        ArgumentNullException.ThrowIfNull(trainSamples);
        ArgumentNullException.ThrowIfNull(testSamples);
        options ??= new MlTrainingOptions();

        if (trainSamples.Count == 0 || testSamples.Count == 0)
        {
            throw new ArgumentException("Les ensembles d'entraînement et de test doivent être non vides.");
        }

        ValidateClassBalance(trainSamples, nameof(trainSamples));
        ValidateClassBalance(testSamples, nameof(testSamples));

        var mlContext = new MLContext(seed: options.Seed);
        var trainView = mlContext.Data.LoadFromEnumerable(trainSamples);
        var testView = mlContext.Data.LoadFromEnumerable(testSamples);

        var trainerOptions = new FastTreeBinaryTrainer.Options
        {
            LabelColumnName = nameof(PeTrainingSample.Label),
            FeatureColumnName = nameof(PeTrainingSample.Features),
            NumberOfTrees = Math.Max(10, options.NumberOfTrees),
            NumberOfLeaves = Math.Max(4, options.NumberOfLeaves),
            MinimumExampleCountPerLeaf = Math.Max(1, options.MinimumExampleCountPerLeaf),
            LearningRate = Math.Clamp(options.LearningRate, 0.005, 1.0),
            Seed = options.Seed
        };

        var trainer = mlContext.BinaryClassification.Trainers.FastTree(trainerOptions);
        var model = trainer.Fit(trainView);

        // Évaluation sur le jeu de test tenu à l'écart
        var scoredTest = model.Transform(testView);
        var mlMetrics = mlContext.BinaryClassification.Evaluate(
            scoredTest,
            labelColumnName: nameof(PeTrainingSample.Label));

        var scoredRows = mlContext.Data.CreateEnumerable<ScoredTestRow>(scoredTest, reuseRowObject: false).ToList();
        var topGlobal = ExtractGlobalFeatureImportance(model);

        var evaluation = ComputeFullEvaluationReport(
            scoredRows,
            mlMetrics,
            trainSamples.Count,
            options.TargetFpr,
            topGlobal);

        var (means, stdDevs) = ComputeFeatureStatistics(trainSamples);

        var metadata = new MlModelMetadata
        {
            Version = string.IsNullOrWhiteSpace(options.Version) ? "2.0.0" : options.Version,
            Algorithm = AlgorithmName,
            TrainedAt = DateTimeOffset.UtcNow,
            Auc = evaluation.Auc,
            RecallAt01Fpr = evaluation.RecallAt01Fpr,
            F1Score = evaluation.F1Score,
            Precision = evaluation.Precision,
            EffectiveFpr = evaluation.EffectiveFpr,
            CalibratedThreshold = evaluation.CalibratedThreshold,
            FeatureCount = PeFeatureVector.FeatureCount,
            DatasetNotice = options.DatasetNotice,
            TrainingSamples = trainSamples.Count,
            EvaluationSamples = testSamples.Count,
            FeatureNames = PeFeatureExtractor.FeatureNames,
            FeatureMeans = means,
            FeatureStdDevs = stdDevs
        };

        string? savedModelPath = null;
        string? savedMetaPath = null;
        if (!string.IsNullOrWhiteSpace(outputModelPath))
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(outputModelPath));
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            mlContext.Model.Save(model, trainView.Schema, outputModelPath);
            savedModelPath = Path.GetFullPath(outputModelPath);

            savedMetaPath = string.IsNullOrWhiteSpace(outputMetadataPath)
                ? Path.ChangeExtension(savedModelPath, ".meta.json")
                : Path.GetFullPath(outputMetadataPath);

            var metaDir = Path.GetDirectoryName(savedMetaPath);
            if (!string.IsNullOrEmpty(metaDir))
            {
                Directory.CreateDirectory(metaDir);
            }

            File.WriteAllText(savedMetaPath, JsonSerializer.Serialize(metadata, JsonOptions));
        }

        return new MlTrainingResult(evaluation, metadata, savedModelPath, savedMetaPath);
    }

    internal static MlEvaluationReport ComputeFullEvaluationReport(
        IReadOnlyList<ScoredTestRow> rows,
        CalibratedBinaryClassificationMetrics mlMetrics,
        int trainCount,
        double targetFpr,
        IReadOnlyList<FeatureImportanceEntry> topGlobalFeatures)
    {
        var positives = rows.Where(r => r.Label).ToList();
        var negatives = rows.Where(r => !r.Label).ToList();

        var rocAuc = double.IsFinite(mlMetrics.AreaUnderRocCurve)
            ? mlMetrics.AreaUnderRocCurve
            : ComputeTrapezoidalRocAuc(rows);

        var prAuc = double.IsFinite(mlMetrics.AreaUnderPrecisionRecallCurve)
            ? mlMetrics.AreaUnderPrecisionRecallCurve
            : 0.0;

        // Calibration du seuil sur le score brut (sans saturation float) pour garantir FPR effectif <= targetFpr
        var maxAllowedFp = (int)Math.Floor(targetFpr * negatives.Count);
        var sortedNegsDesc = negatives.OrderByDescending(r => r.Score).ToList();

        double scoreThreshold;
        double probThreshold;

        if (negatives.Count == 0)
        {
            scoreThreshold = 0.0;
            probThreshold = 0.5;
        }
        else if (maxAllowedFp >= negatives.Count)
        {
            scoreThreshold = double.NegativeInfinity;
            probThreshold = 0.0;
        }
        else
        {
            // Le (maxAllowedFp + 1)-ième négatif le plus élevé ne doit PAS être classé positif
            var cutoffNeg = sortedNegsDesc[maxAllowedFp];
            var minPosAbove = positives
                .Where(p => p.Score > cutoffNeg.Score)
                .OrderBy(p => p.Score)
                .FirstOrDefault();

            if (minPosAbove is not null)
            {
                scoreThreshold = 0.5 * ((double)cutoffNeg.Score + minPosAbove.Score);
                probThreshold = Math.Clamp(0.5 * ((double)cutoffNeg.Probability + minPosAbove.Probability), 0.0, 1.0);
            }
            else
            {
                scoreThreshold = cutoffNeg.Score + 1e-4;
                probThreshold = Math.Clamp(cutoffNeg.Probability + 1e-4, 0.0, 1.0);
            }
        }

        var tpAtTarget = positives.Count(p => p.Score >= scoreThreshold);
        var fpAtTarget = negatives.Count(n => n.Score >= scoreThreshold);
        var tnAtTarget = negatives.Count - fpAtTarget;
        var fnAtTarget = positives.Count - tpAtTarget;

        var recallAtTarget = positives.Count > 0 ? (double)tpAtTarget / positives.Count : 0.0;
        var effectiveFpr = negatives.Count > 0 ? (double)fpAtTarget / negatives.Count : 0.0;
        var precisionAtTarget = (tpAtTarget + fpAtTarget) > 0
            ? (double)tpAtTarget / (tpAtTarget + fpAtTarget)
            : 0.0;
        var f1AtTarget = (precisionAtTarget + recallAtTarget) > 0
            ? 2.0 * precisionAtTarget * recallAtTarget / (precisionAtTarget + recallAtTarget)
            : 0.0;

        // Métriques standards au seuil 0.5 (Score >= 0)
        var tpStd = positives.Count(p => p.Probability >= 0.5f);
        var fpStd = negatives.Count(n => n.Probability >= 0.5f);
        var tnStd = negatives.Count - fpStd;
        var precisionStd = (tpStd + fpStd) > 0 ? (double)tpStd / (tpStd + fpStd) : 0.0;
        var recallStd = positives.Count > 0 ? (double)tpStd / positives.Count : 0.0;
        var f1Std = (precisionStd + recallStd) > 0
            ? 2.0 * precisionStd * recallStd / (precisionStd + recallStd)
            : 0.0;
        var accuracy = rows.Count > 0 ? (double)(tpStd + tnStd) / rows.Count : 0.0;

        return new MlEvaluationReport(
            Auc: Math.Clamp(rocAuc, 0.0, 1.0),
            PrAuc: Math.Clamp(prAuc, 0.0, 1.0),
            RecallAt01Fpr: recallAtTarget,
            EffectiveFpr: effectiveFpr,
            CalibratedThreshold: probThreshold,
            CalibratedScoreThreshold: scoreThreshold,
            F1Score: f1Std,
            Precision: precisionStd,
            Recall: recallStd,
            PrecisionAt01Fpr: precisionAtTarget,
            F1At01Fpr: f1AtTarget,
            Accuracy: accuracy,
            TrainCount: trainCount,
            TestCount: rows.Count,
            TestPositives: positives.Count,
            TestNegatives: negatives.Count,
            TruePositivesAt01Fpr: tpAtTarget,
            FalsePositivesAt01Fpr: fpAtTarget,
            TrueNegativesAt01Fpr: tnAtTarget,
            FalseNegativesAt01Fpr: fnAtTarget,
            TopGlobalFeatures: topGlobalFeatures);
    }

    private static double ComputeTrapezoidalRocAuc(IReadOnlyList<ScoredTestRow> rows)
    {
        var totalPos = rows.Count(r => r.Label);
        var totalNeg = rows.Count - totalPos;
        if (totalPos == 0 || totalNeg == 0) return 0.0;

        var ordered = rows.OrderByDescending(r => r.Score).ToList();
        double tp = 0, fp = 0, prevTp = 0, prevFp = 0, auc = 0;

        for (var i = 0; i < ordered.Count; i++)
        {
            if (ordered[i].Label) tp++; else fp++;

            if (i == ordered.Count - 1 || Math.Abs(ordered[i].Score - ordered[i + 1].Score) > 1e-9f)
            {
                auc += (fp - prevFp) * (tp + prevTp) * 0.5;
                prevTp = tp;
                prevFp = fp;
            }
        }

        return auc / (totalPos * (double)totalNeg);
    }

    private static IReadOnlyList<FeatureImportanceEntry> ExtractGlobalFeatureImportance(
        BinaryPredictionTransformer<CalibratedModelParametersBase<FastTreeBinaryModelParameters, PlattCalibrator>> model)
    {
        try
        {
            VBuffer<float> weights = default;
            model.Model.SubModel.GetFeatureWeights(ref weights);
            var dense = weights.DenseValues().ToArray();

            var list = new List<FeatureImportanceEntry>(dense.Length);
            for (var i = 0; i < dense.Length && i < PeFeatureExtractor.FeatureNames.Count; i++)
            {
                if (dense[i] > 0f)
                {
                    list.Add(new FeatureImportanceEntry(i, PeFeatureExtractor.FeatureNames[i], dense[i]));
                }
            }

            return list.OrderByDescending(e => e.Gain).Take(10).ToList();
        }
        catch
        {
            return Array.Empty<FeatureImportanceEntry>();
        }
    }

    private static (float[] Means, float[] StdDevs) ComputeFeatureStatistics(IReadOnlyList<PeTrainingSample> samples)
    {
        var n = samples.Count;
        var means = new double[PeFeatureVector.FeatureCount];
        var m2 = new double[PeFeatureVector.FeatureCount];

        // Algorithme de Welford pour la stabilité numérique
        var count = 0;
        foreach (var s in samples)
        {
            count++;
            for (var i = 0; i < PeFeatureVector.FeatureCount; i++)
            {
                var x = s.Features[i];
                var delta = x - means[i];
                means[i] += delta / count;
                var delta2 = x - means[i];
                m2[i] += delta * delta2;
            }
        }

        var meanF = new float[PeFeatureVector.FeatureCount];
        var stdF = new float[PeFeatureVector.FeatureCount];
        for (var i = 0; i < PeFeatureVector.FeatureCount; i++)
        {
            meanF[i] = (float)means[i];
            var variance = n > 1 ? m2[i] / (n - 1) : 1.0;
            stdF[i] = (float)Math.Max(1e-4, Math.Sqrt(Math.Max(0.0, variance)));
        }

        return (meanF, stdF);
    }

    private static void ValidateClassBalance(IReadOnlyList<PeTrainingSample> samples, string paramName)
    {
        var hasPos = false;
        var hasNeg = false;
        foreach (var s in samples)
        {
            if (s.Label) hasPos = true; else hasNeg = true;
            if (hasPos && hasNeg) return;
        }

        throw new ArgumentException(
            "Le jeu de données doit contenir au moins un échantillon bénin (false) et un échantillon malveillant (true).",
            paramName);
    }

    internal sealed class ScoredTestRow
    {
        public bool Label { get; set; }
        public float Score { get; set; }
        public float Probability { get; set; }
        public bool PredictedLabel { get; set; }
    }
}
