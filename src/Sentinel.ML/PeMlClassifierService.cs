using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.ML;
using Microsoft.ML.Calibrators;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;
using Microsoft.ML.Trainers.FastTree;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Models;

namespace Sentinel.ML;

/// <summary>
/// Service d'inférence thread-safe du classifieur PE ML.NET avec explicabilité par caractéristiques
/// (<c>CalculateFeatureContribution</c> sur FastTree, ou z-scores en repli).
/// Garantit une contribution strictement plafonnée (jamais seule décisive).
/// </summary>
public sealed class PeMlClassifierService : IPeMlClassifier, IDisposable
{
    /// <summary>
    /// Plafond de sécurité absolu, strictement inférieur à <see cref="ThreatThresholds.Moderate"/> (55),
    /// afin que le classifieur ML seul ne puisse jamais déclencher une alerte modérée/élevée/critique ni un blocage.
    /// </summary>
    public const int AbsoluteSafetyScoreCeiling = 50;

    private const int MinExplanations = 3;
    private const int MaxExplanations = 5;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly object _sync = new();
    private readonly MLContext _mlContext = new(seed: 42);
    private readonly PeFeatureExtractor _extractor;
    private readonly Func<MlSettings> _settingsAccessor;
    private readonly ILogger<PeMlClassifierService>? _logger;

    private string _modelPath;
    private string _metadataPath;
    private PredictionEngine<PeTrainingSample, BinaryPredictionRow>? _predictionEngine;
    private PredictionEngine<PeTrainingSample, FeatureContributionRow>? _contributionEngine;
    private MlModelMetadata? _metadata;
    private bool _loaded;
    private bool _disposed;

    public PeMlClassifierService(
        string? modelPath = null,
        string? metadataPath = null,
        MlSettings? settings = null,
        PeFeatureExtractor? extractor = null,
        ILogger<PeMlClassifierService>? logger = null)
        : this(
            modelPath,
            metadataPath,
            settings is not null ? () => settings : () => new MlSettings(),
            extractor,
            logger)
    {
    }

    public PeMlClassifierService(
        string? modelPath,
        string? metadataPath,
        Func<MlSettings> settingsAccessor,
        PeFeatureExtractor? extractor = null,
        ILogger<PeMlClassifierService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(settingsAccessor);
        _settingsAccessor = settingsAccessor;
        _extractor = extractor ?? new PeFeatureExtractor();
        _logger = logger;
        _modelPath = string.IsNullOrWhiteSpace(modelPath) ? SentinelPaths.MlModelFile : modelPath;
        _metadataPath = string.IsNullOrWhiteSpace(metadataPath)
            ? (string.IsNullOrWhiteSpace(modelPath) ? SentinelPaths.MlModelMetadataFile : Path.ChangeExtension(_modelPath, ".meta.json"))
            : metadataPath;

        Reload(_modelPath, _metadataPath);
    }

    /// <summary>Charge ou recharge de manière atomique le modèle <c>.zip</c> et ses métadonnées JSON.</summary>
    public bool Reload(string? modelPath = null, string? metadataPath = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var targetModelPath = string.IsNullOrWhiteSpace(modelPath) ? _modelPath : modelPath;
        var targetMetaPath = string.IsNullOrWhiteSpace(metadataPath)
            ? (string.IsNullOrWhiteSpace(modelPath) ? _metadataPath : Path.ChangeExtension(targetModelPath, ".meta.json"))
            : metadataPath;

        if (!File.Exists(targetModelPath))
        {
            _logger?.LogWarning("Modèle ML PE introuvable à '{ModelPath}'. Inférence ML désactivée jusqu'au chargement d'un modèle.", targetModelPath);
            lock (_sync)
            {
                _modelPath = targetModelPath;
                _metadataPath = targetMetaPath;
                DisposeEnginesLocked();
                _metadata = null;
                _loaded = false;
            }
            return false;
        }

        PredictionEngine<PeTrainingSample, BinaryPredictionRow>? newPredEngine = null;
        PredictionEngine<PeTrainingSample, FeatureContributionRow>? newFccEngine = null;
        MlModelMetadata? newMeta = null;

        try
        {
            var loadedTransformer = _mlContext.Model.Load(targetModelPath, out _);
            newPredEngine = _mlContext.Model.CreatePredictionEngine<PeTrainingSample, BinaryPredictionRow>(loadedTransformer);
            newFccEngine = TryCreateContributionEngine(loadedTransformer);

            if (File.Exists(targetMetaPath))
            {
                var json = File.ReadAllText(targetMetaPath);
                newMeta = JsonSerializer.Deserialize<MlModelMetadata>(json, JsonOptions);
            }

            newMeta ??= new MlModelMetadata
            {
                Version = "unversioned",
                Algorithm = PeClassifierTrainer.AlgorithmName,
                FeatureCount = PeFeatureVector.FeatureCount,
                DatasetNotice = "Fichier de métadonnées absent lors du chargement du modèle."
            };

            lock (_sync)
            {
                DisposeEnginesLocked();
                _modelPath = targetModelPath;
                _metadataPath = targetMetaPath;
                _predictionEngine = newPredEngine;
                _contributionEngine = newFccEngine;
                _metadata = newMeta;
                _loaded = true;
            }

            _logger?.LogInformation(
                "Modèle ML PE chargé : version={Version}, AUC={Auc:F4}, Recall@0.1%FPR={Recall:F4}, FCC={FccEnabled}.",
                newMeta.Version, newMeta.Auc, newMeta.RecallAt01Fpr, newFccEngine is not null);

            return true;
        }
        catch (Exception ex)
        {
            newPredEngine?.Dispose();
            newFccEngine?.Dispose();
            _logger?.LogError(ex, "Échec du chargement du modèle ML PE depuis '{ModelPath}'.", targetModelPath);
            return false;
        }
    }

    /// <summary>Extrait les caractéristiques statiques d'un fichier PE sur disque puis exécute l'inférence ML.</summary>
    public MlPredictionResult PredictFile(string filePath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var settings = _settingsAccessor();
        if (!settings.Enabled)
        {
            return CreateEmptyResult(GetCurrentVersion(), _loaded);
        }

        if (!_loaded)
        {
            return CreateEmptyResult("none", modelLoaded: false);
        }

        if (!_extractor.TryExtract(filePath, out var features, out var error) || features is null)
        {
            _logger?.LogDebug("Extraction PE ignorée pour '{FilePath}' : {Error}", filePath, error);
            return CreateEmptyResult(GetCurrentVersion(), modelLoaded: true);
        }

        return PredictFeatures(features);
    }

    /// <summary>Exécute l'inférence ML et l'explicabilité sur un vecteur de caractéristiques déjà extrait.</summary>
    public MlPredictionResult PredictFeatures(PeFeatureVector features)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(features);

        var settings = _settingsAccessor();
        if (!settings.Enabled)
        {
            return CreateEmptyResult(GetCurrentVersion(), _loaded);
        }

        BinaryPredictionRow pred;
        float[]? contributions = null;
        MlModelMetadata? metaSnapshot;

        var input = features.ToTrainingSample();

        lock (_sync)
        {
            if (!_loaded || _predictionEngine is null)
            {
                return CreateEmptyResult("none", modelLoaded: false);
            }

            pred = _predictionEngine.Predict(input);
            metaSnapshot = _metadata;

            if (_contributionEngine is not null)
            {
                try
                {
                    var contribPred = _contributionEngine.Predict(input);
                    contributions = contribPred.FeatureContributions;
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Calcul CalculateFeatureContribution indisponible ; bascule vers l'explicabilité z-score.");
                }
            }
        }

        var probability = float.IsFinite(pred.Probability)
            ? Math.Clamp((double)pred.Probability, 0.0, 1.0)
            : 0.0;

        var boundedScore = ComputeBoundedScoreContribution(probability, settings);
        var explanations = BuildTopContributingFeatures(features, probability, contributions, metaSnapshot);
        var version = metaSnapshot?.Version ?? "unknown";

        return new MlPredictionResult(
            MaliciousProbability: probability,
            BoundedScoreContribution: boundedScore,
            TopContributingFeatures: explanations,
            ModelVersion: version,
            ModelLoaded: true);
    }

    /// <summary>Retourne l'état courant du modèle pour la console d'administration SENTINEL.</summary>
    public MlModelStatusDto GetStatus()
    {
        lock (_sync)
        {
            if (!_loaded || _metadata is null)
            {
                return new MlModelStatusDto(
                    Loaded: false,
                    Version: "none",
                    Algorithm: PeClassifierTrainer.AlgorithmName,
                    TrainedAt: null,
                    Auc: 0.0,
                    RecallAt01Fpr: 0.0,
                    F1Score: 0.0,
                    FeatureCount: PeFeatureVector.FeatureCount,
                    DatasetNotice: "Aucun modèle ML PE chargé.",
                    ModelPath: _modelPath);
            }

            return new MlModelStatusDto(
                Loaded: true,
                Version: _metadata.Version,
                Algorithm: _metadata.Algorithm,
                TrainedAt: _metadata.TrainedAt,
                Auc: _metadata.Auc,
                RecallAt01Fpr: _metadata.RecallAt01Fpr,
                F1Score: _metadata.F1Score,
                FeatureCount: _metadata.FeatureCount,
                DatasetNotice: _metadata.DatasetNotice,
                ModelPath: _modelPath);
        }
    }

    /// <summary>
    /// Calcule la contribution au score de menace à partir de la probabilité malveillante.
    /// Strictement plafonnée à <c>min(MlSettings.MaxScoreContribution, AbsoluteSafetyScoreCeiling)</c>
    /// pour garantir que le ML ne soit jamais seul décisif.
    /// </summary>
    public static int ComputeBoundedScoreContribution(double probability, MlSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.Enabled || !double.IsFinite(probability))
        {
            return 0;
        }

        var p = Math.Clamp(probability, 0.0, 1.0);
        var effectiveCap = Math.Clamp(settings.MaxScoreContribution, 0, AbsoluteSafetyScoreCeiling);
        if (effectiveCap == 0)
        {
            return 0;
        }

        var threshold = Math.Clamp(settings.SuspiciousProbabilityThreshold, 0.25, 0.99);
        const double noiseFloor = 0.15;

        if (p <= noiseFloor)
        {
            return 0;
        }

        double scaled;
        if (p < threshold)
        {
            // Signal informationnel faible sous le seuil de suspicion (au plus 30 % du plafond)
            var ratio = (p - noiseFloor) / Math.Max(0.05, threshold - noiseFloor);
            scaled = effectiveCap * 0.30 * ratio;
        }
        else
        {
            // Contribution progressive de 40 % à 100 % du plafond au-delà du seuil
            var ratio = (p - threshold) / Math.Max(0.01, 1.0 - threshold);
            scaled = effectiveCap * (0.40 + 0.60 * ratio);
        }

        return Math.Clamp((int)Math.Round(scaled, MidpointRounding.AwayFromZero), 0, effectiveCap);
    }

    private PredictionEngine<PeTrainingSample, FeatureContributionRow>? TryCreateContributionEngine(ITransformer transformer)
    {
        try
        {
            var emptyData = _mlContext.Data.LoadFromEnumerable(Array.Empty<PeTrainingSample>());

            if (TryUnwrapCalibratedFastTree(transformer, out var calibratedFastTree) && calibratedFastTree is not null)
            {
                var estimator = _mlContext.Transforms.CalculateFeatureContribution(
                    calibratedFastTree,
                    numberOfPositiveContributions: PeFeatureVector.FeatureCount,
                    numberOfNegativeContributions: PeFeatureVector.FeatureCount,
                    normalize: false);

                var fccTransformer = estimator.Fit(emptyData);
                return _mlContext.Model.CreatePredictionEngine<PeTrainingSample, FeatureContributionRow>(fccTransformer);
            }

            if (TryUnwrapFeatureContributionTransformer(transformer, out var directFcc) && directFcc is not null)
            {
                var estimator = _mlContext.Transforms.CalculateFeatureContribution(
                    directFcc,
                    numberOfPositiveContributions: PeFeatureVector.FeatureCount,
                    numberOfNegativeContributions: PeFeatureVector.FeatureCount,
                    normalize: false);

                var fccTransformer = estimator.Fit(emptyData);
                return _mlContext.Model.CreatePredictionEngine<PeTrainingSample, FeatureContributionRow>(fccTransformer);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Impossible d'initialiser FeatureContributionCalculatingTransformer ; repli z-score actif.");
        }

        return null;
    }

    private static bool TryUnwrapCalibratedFastTree(
        ITransformer transformer,
        out ISingleFeaturePredictionTransformer<CalibratedModelParametersBase<FastTreeBinaryModelParameters, PlattCalibrator>>? found)
    {
        if (transformer is ISingleFeaturePredictionTransformer<CalibratedModelParametersBase<FastTreeBinaryModelParameters, PlattCalibrator>> direct)
        {
            found = direct;
            return true;
        }

        if (transformer is IEnumerable<ITransformer> chain)
        {
            foreach (var step in chain)
            {
                if (TryUnwrapCalibratedFastTree(step, out found))
                {
                    return true;
                }
            }
        }

        found = null;
        return false;
    }

    private static bool TryUnwrapFeatureContributionTransformer(
        ITransformer transformer,
        out ISingleFeaturePredictionTransformer<ICalculateFeatureContribution>? found)
    {
        if (transformer is ISingleFeaturePredictionTransformer<ICalculateFeatureContribution> direct)
        {
            found = direct;
            return true;
        }

        if (transformer is IEnumerable<ITransformer> chain)
        {
            foreach (var step in chain)
            {
                if (TryUnwrapFeatureContributionTransformer(step, out found))
                {
                    return true;
                }
            }
        }

        found = null;
        return false;
    }

    private static IReadOnlyList<string> BuildTopContributingFeatures(
        PeFeatureVector features,
        double probability,
        float[]? modelContributions,
        MlModelMetadata? metadata)
    {
        // 1) Méthode principale : contributions exactes par splits FastTree (ML.NET CalculateFeatureContribution)
        if (modelContributions is not null && modelContributions.Length == PeFeatureVector.FeatureCount)
        {
            var indexed = new List<(int Index, float Contrib)>(PeFeatureVector.FeatureCount);
            for (var i = 0; i < PeFeatureVector.FeatureCount; i++)
            {
                var c = modelContributions[i];
                if (float.IsFinite(c) && MathF.Abs(c) > 1e-6f)
                {
                    indexed.Add((i, c));
                }
            }

            if (indexed.Count > 0)
            {
                // Pour une prédiction suspecte : prioriser les contributions positives (pro-malveillant) ;
                // pour une prédiction bénigne : prioriser les contributions négatives (pro-bénin)
                var aligned = probability >= 0.5
                    ? indexed.Where(x => x.Contrib > 0f).OrderByDescending(x => x.Contrib).ToList()
                    : indexed.Where(x => x.Contrib < 0f).OrderBy(x => x.Contrib).ToList();

                var selected = new List<int>(MaxExplanations);
                foreach (var item in aligned)
                {
                    if (selected.Count >= MaxExplanations) break;
                    selected.Add(item.Index);
                }

                if (selected.Count < MinExplanations)
                {
                    foreach (var item in indexed.OrderByDescending(x => MathF.Abs(x.Contrib)))
                    {
                        if (selected.Count >= MaxExplanations) break;
                        if (!selected.Contains(item.Index))
                        {
                            selected.Add(item.Index);
                        }
                    }
                }

                if (selected.Count > 0)
                {
                    var formatted = new List<string>(selected.Count);
                    foreach (var idx in selected)
                    {
                        formatted.Add(PeFeatureExtractor.FormatFeatureValue(idx, features[idx]));
                    }
                    return formatted;
                }
            }
        }

        // 2) Repli déterministe : z-scores par rapport aux moyennes/écarts-types d'entraînement
        return BuildZScoreFallbackExplanations(features, metadata);
    }

    private static IReadOnlyList<string> BuildZScoreFallbackExplanations(
        PeFeatureVector features,
        MlModelMetadata? metadata)
    {
        var hasStats = metadata?.FeatureMeans is { Length: PeFeatureVector.FeatureCount } &&
                       metadata.FeatureStdDevs is { Length: PeFeatureVector.FeatureCount };

        var ranked = new List<(int Index, double Score)>(PeFeatureVector.FeatureCount);
        for (var i = 0; i < PeFeatureVector.FeatureCount; i++)
        {
            double magnitude;
            if (hasStats)
            {
                var mean = metadata!.FeatureMeans![i];
                var std = Math.Max(1e-4f, metadata.FeatureStdDevs![i]);
                magnitude = Math.Abs((features[i] - mean) / std);
            }
            else
            {
                magnitude = Math.Abs(features[i]);
            }

            ranked.Add((i, magnitude));
        }

        var top = ranked
            .OrderByDescending(x => x.Score)
            .Take(MaxExplanations)
            .Select(x => PeFeatureExtractor.FormatFeatureValue(x.Index, features[x.Index]))
            .ToList();

        return top;
    }

    private static MlPredictionResult CreateEmptyResult(string version, bool modelLoaded) =>
        new(0.0, 0, Array.Empty<string>(), version, modelLoaded);

    private string GetCurrentVersion()
    {
        lock (_sync)
        {
            return _metadata?.Version ?? "none";
        }
    }

    private void DisposeEnginesLocked()
    {
        _predictionEngine?.Dispose();
        _predictionEngine = null;
        _contributionEngine?.Dispose();
        _contributionEngine = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        lock (_sync)
        {
            DisposeEnginesLocked();
            _loaded = false;
            _disposed = true;
        }
    }

    private sealed class BinaryPredictionRow
    {
        [ColumnName("PredictedLabel")]
        public bool PredictedLabel { get; set; }

        [ColumnName("Score")]
        public float Score { get; set; }

        [ColumnName("Probability")]
        public float Probability { get; set; }
    }

    private sealed class FeatureContributionRow
    {
        [ColumnName("Score")]
        public float Score { get; set; }

        [ColumnName("FeatureContributions")]
        [VectorType(PeFeatureVector.FeatureCount)]
        public float[]? FeatureContributions { get; set; }
    }
}
