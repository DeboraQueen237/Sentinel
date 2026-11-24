using Sentinel.Shared.Api;

namespace Sentinel.ML;

/// <summary>
/// Options d'entraînement du classifieur binaire ML.NET FastTree sur vecteurs PE.
/// </summary>
public sealed class MlTrainingOptions
{
    public string Version { get; set; } = "2.0.0-synthetic";
    public string DatasetNotice { get; set; } = SyntheticPeDatasetGenerator.DefaultDatasetNotice;
    public double TestFraction { get; set; } = 0.2;
    public int Seed { get; set; } = 42;
    public int NumberOfTrees { get; set; } = 120;
    public int NumberOfLeaves { get; set; } = 31;
    public int MinimumExampleCountPerLeaf { get; set; } = 10;
    public double LearningRate { get; set; } = 0.1;
    public double TargetFpr { get; set; } = 0.001; // 0,1 % FPR
}

/// <summary>
/// Importance globale d'une caractéristique (gain cumulé dans l'ensemble d'arbres FastTree).
/// </summary>
public sealed record FeatureImportanceEntry(int Index, string Name, double Gain);

/// <summary>
/// Métadonnées versionnées sauvegardées à côté du fichier modèle <c>pe-classifier.zip</c>.
/// </summary>
public sealed class MlModelMetadata
{
    public string Version { get; set; } = "unknown";
    public string Algorithm { get; set; } = "ML.NET FastTreeBinaryTrainer";
    public DateTimeOffset TrainedAt { get; set; } = DateTimeOffset.UtcNow;
    public double Auc { get; set; }
    public double RecallAt01Fpr { get; set; }
    public double F1Score { get; set; }
    public double Precision { get; set; }
    public double EffectiveFpr { get; set; }
    public double CalibratedThreshold { get; set; } = 0.65;
    public int FeatureCount { get; set; } = PeFeatureVector.FeatureCount;
    public string DatasetNotice { get; set; } = string.Empty;
    public int TrainingSamples { get; set; }
    public int EvaluationSamples { get; set; }
    public IReadOnlyList<string> FeatureNames { get; set; } = PeFeatureExtractor.FeatureNames;
    /// <summary>Moyennes par caractéristique sur le jeu d'entraînement (repli z-score pour l'explicabilité).</summary>
    public float[]? FeatureMeans { get; set; }
    /// <summary>Écarts-types par caractéristique sur le jeu d'entraînement (repli z-score pour l'explicabilité).</summary>
    public float[]? FeatureStdDevs { get; set; }
}

/// <summary>
/// Rapport complet d'évaluation produit par <see cref="PeClassifierTrainer"/>.
/// </summary>
public sealed record MlEvaluationReport(
    double Auc,
    double PrAuc,
    double RecallAt01Fpr,
    double EffectiveFpr,
    double CalibratedThreshold,
    double CalibratedScoreThreshold,
    double F1Score,
    double Precision,
    double Recall,
    double PrecisionAt01Fpr,
    double F1At01Fpr,
    double Accuracy,
    int TrainCount,
    int TestCount,
    int TestPositives,
    int TestNegatives,
    int TruePositivesAt01Fpr,
    int FalsePositivesAt01Fpr,
    int TrueNegativesAt01Fpr,
    int FalseNegativesAt01Fpr,
    IReadOnlyList<FeatureImportanceEntry> TopGlobalFeatures);

/// <summary>
/// Résultat d'une session d'entraînement complète (rapport + métadonnées + chemins produits).
/// </summary>
public sealed record MlTrainingResult(
    MlEvaluationReport Evaluation,
    MlModelMetadata Metadata,
    string? SavedModelPath,
    string? SavedMetadataPath);

/// <summary>
/// Résultat d'inférence ML sur un binaire PE ou son vecteur de caractéristiques.
/// La contribution <see cref="BoundedScoreContribution"/> est strictement plafonnée et jamais seule décisive.
/// </summary>
public sealed record MlPredictionResult(
    double MaliciousProbability,
    int BoundedScoreContribution,
    IReadOnlyList<string> TopContributingFeatures,
    string ModelVersion,
    bool ModelLoaded);

/// <summary>
/// Contrat d'inférence du classifieur statique ML PE dans SENTINEL v2.
/// </summary>
public interface IPeMlClassifier
{
    MlPredictionResult PredictFile(string filePath);
    MlPredictionResult PredictFeatures(PeFeatureVector features);
    MlModelStatusDto GetStatus();
    bool Reload(string? modelPath = null, string? metadataPath = null);
}
