using System.Globalization;
using Sentinel.ML;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Models;

namespace Sentinel.ML.Trainer;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "--help" or "-h" or "/?"))
        {
            PrintUsage();
            return 0;
        }

        var useSynthetic = false;
        string? csvPath = null;
        string? emberJsonlPath = null;
        string? inspectPath = null;
        string? outputDir = null;
        string? version = null;
        var sampleCount = 10000;
        int? maxSamples = null;
        var seed = 42;
        var trees = 120;
        var leaves = 31;
        var learningRate = 0.1;
        var testFraction = 0.2;

        try
        {
            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                switch (arg)
                {
                    case "--synthetic":
                        useSynthetic = true;
                        break;
                    case "--csv":
                        csvPath = RequireValue(args, ref i, "--csv");
                        break;
                    case "--ember-jsonl":
                        emberJsonlPath = RequireValue(args, ref i, "--ember-jsonl");
                        break;
                    case "--inspect":
                        inspectPath = RequireValue(args, ref i, "--inspect");
                        break;
                    case "--output":
                    case "-o":
                        outputDir = RequireValue(args, ref i, arg);
                        break;
                    case "--version":
                        version = RequireValue(args, ref i, "--version");
                        break;
                    case "--samples":
                        sampleCount = int.Parse(RequireValue(args, ref i, "--samples"), CultureInfo.InvariantCulture);
                        break;
                    case "--max-samples":
                        maxSamples = int.Parse(RequireValue(args, ref i, "--max-samples"), CultureInfo.InvariantCulture);
                        break;
                    case "--seed":
                        seed = int.Parse(RequireValue(args, ref i, "--seed"), CultureInfo.InvariantCulture);
                        break;
                    case "--trees":
                        trees = int.Parse(RequireValue(args, ref i, "--trees"), CultureInfo.InvariantCulture);
                        break;
                    case "--leaves":
                        leaves = int.Parse(RequireValue(args, ref i, "--leaves"), CultureInfo.InvariantCulture);
                        break;
                    case "--learning-rate":
                        learningRate = double.Parse(RequireValue(args, ref i, "--learning-rate"), CultureInfo.InvariantCulture);
                        break;
                    case "--test-fraction":
                        testFraction = double.Parse(RequireValue(args, ref i, "--test-fraction"), CultureInfo.InvariantCulture);
                        break;
                    default:
                        Console.Error.WriteLine($"Option inconnue : '{arg}'. Utilisez --help pour l'aide.");
                        return 1;
                }
            }

            if (!string.IsNullOrWhiteSpace(inspectPath))
            {
                return RunInspect(inspectPath, outputDir);
            }

            var modeCount = (useSynthetic ? 1 : 0) +
                            (!string.IsNullOrWhiteSpace(csvPath) ? 1 : 0) +
                            (!string.IsNullOrWhiteSpace(emberJsonlPath) ? 1 : 0);

            if (modeCount != 1)
            {
                Console.Error.WriteLine("Veuillez spécifier exactement une source : --synthetic, --csv <chemin> ou --ember-jsonl <chemin>.");
                return 1;
            }

            var resolvedOutputDir = string.IsNullOrWhiteSpace(outputDir)
                ? SentinelPaths.Models
                : Path.GetFullPath(outputDir);
            Directory.CreateDirectory(resolvedOutputDir);

            var modelPath = Path.Combine(resolvedOutputDir, "pe-classifier.zip");
            var metaPath = Path.Combine(resolvedOutputDir, "pe-classifier.meta.json");

            IReadOnlyList<PeTrainingSample> dataset;
            string datasetNotice;
            string defaultVersion;

            if (useSynthetic)
            {
                Console.WriteLine($"[Sentinel.ML.Trainer] Génération du jeu synthétique ({sampleCount} échantillons, graine={seed})...");
                dataset = SyntheticPeDatasetGenerator.Generate(sampleCount, seed);
                datasetNotice = SyntheticPeDatasetGenerator.DefaultDatasetNotice;
                defaultVersion = "2.0.0-synthetic";
            }
            else if (!string.IsNullOrWhiteSpace(csvPath))
            {
                Console.WriteLine($"[Sentinel.ML.Trainer] Chargement du CSV : {csvPath}");
                dataset = PeDatasetLoader.LoadFromCsv(csvPath, maxSamples);
                datasetNotice = $"Dataset CSV fourni par l'utilisateur hors dépôt ({Path.GetFileName(csvPath)}, {dataset.Count} échantillons étiquetés).";
                defaultVersion = "2.0.0-csv";
            }
            else
            {
                Console.WriteLine($"[Sentinel.ML.Trainer] Chargement du JSONL EMBER : {emberJsonlPath}");
                dataset = PeDatasetLoader.LoadFromEmberJsonl(emberJsonlPath!, maxSamples);
                datasetNotice = $"Dataset EMBER JSONL fourni légalement par l'utilisateur hors dépôt ({Path.GetFileName(emberJsonlPath)}, {dataset.Count} échantillons étiquetés).";
                defaultVersion = "2.0.0-ember";
            }

            var options = new MlTrainingOptions
            {
                Version = string.IsNullOrWhiteSpace(version) ? defaultVersion : version,
                DatasetNotice = datasetNotice,
                TestFraction = testFraction,
                Seed = seed,
                NumberOfTrees = trees,
                NumberOfLeaves = leaves,
                LearningRate = learningRate
            };

            Console.WriteLine($"[Sentinel.ML.Trainer] Entraînement FastTree (arbres={options.NumberOfTrees}, feuilles={options.NumberOfLeaves}, lr={options.LearningRate.ToString("0.###", CultureInfo.InvariantCulture)})...");

            var trainer = new PeClassifierTrainer();
            var result = trainer.TrainAndEvaluate(dataset, options, modelPath, metaPath);
            var eval = result.Evaluation;

            Console.WriteLine();
            Console.WriteLine("=== Résultats d'évaluation SENTINEL ML (PE FastTree) ===");
            Console.WriteLine($"Version modèle          : {result.Metadata.Version}");
            Console.WriteLine($"Algorithme              : {result.Metadata.Algorithm}");
            Console.WriteLine($"Caractéristiques        : {result.Metadata.FeatureCount}");
            Console.WriteLine($"Train / Test            : {eval.TrainCount} / {eval.TestCount} (pos={eval.TestPositives}, neg={eval.TestNegatives})");
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"ROC-AUC                 : {eval.Auc:F4}"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"PR-AUC                  : {eval.PrAuc:F4}"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Recall @ 0.1% FPR       : {eval.RecallAt01Fpr:F4} (TP={eval.TruePositivesAt01Fpr}, FP={eval.FalsePositivesAt01Fpr}, FPR effectif={eval.EffectiveFpr:P3})"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Seuil calibré (0.1%FPR) : prob={eval.CalibratedThreshold:F4} (score brut={eval.CalibratedScoreThreshold:F4})"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"F1 / Précision (0.5)    : F1={eval.F1Score:F4} | Précision={eval.Precision:F4} | Rappel={eval.Recall:F4} | Exactitude={eval.Accuracy:F4}"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"F1 / Précision (0.1%FPR): F1={eval.F1At01Fpr:F4} | Précision={eval.PrecisionAt01Fpr:F4}"));
            Console.WriteLine($"Notice dataset          : {result.Metadata.DatasetNotice}");
            Console.WriteLine($"Modèle sauvegardé       : {result.SavedModelPath}");
            Console.WriteLine($"Métadonnées sauvegardées: {result.SavedMetadataPath}");

            if (eval.TopGlobalFeatures.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Top caractéristiques globales (gain FastTree) :");
                foreach (var feat in eval.TopGlobalFeatures.Take(8))
                {
                    Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  - {feat.Name,-32} gain={feat.Gain:F4}"));
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Erreur] {ex.Message}");
            return 1;
        }
    }

    private static int RunInspect(string filePath, string? outputDir)
    {
        var extractor = new PeFeatureExtractor();
        if (!extractor.TryExtract(filePath, out var vector, out var error) || vector is null)
        {
            Console.Error.WriteLine($"[Inspect] Échec extraction PE : {error}");
            return 1;
        }

        Console.WriteLine($"=== Caractéristiques PE extraites : {Path.GetFileName(filePath)} ({PeFeatureVector.FeatureCount} features) ===");
        for (var i = 0; i < PeFeatureExtractor.FeatureNames.Count; i++)
        {
            Console.WriteLine($"  [{i:D2}] {PeFeatureExtractor.FormatFeatureValue(i, vector[i])}");
        }

        var resolvedDir = string.IsNullOrWhiteSpace(outputDir) ? SentinelPaths.Models : Path.GetFullPath(outputDir);
        var modelPath = Path.Combine(resolvedDir, "pe-classifier.zip");
        if (File.Exists(modelPath))
        {
            using var classifier = new PeMlClassifierService(modelPath, settings: new MlSettings());
            var pred = classifier.PredictFeatures(vector);
            Console.WriteLine();
            Console.WriteLine($"=== Inférence ML (modèle {pred.ModelVersion}) ===");
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Probabilité malveillante : {pred.MaliciousProbability:F4}"));
            Console.WriteLine($"Contribution plafonnée   : {pred.BoundedScoreContribution}/{new MlSettings().MaxScoreContribution}");
            Console.WriteLine($"Facteurs explicatifs     : {string.Join(", ", pred.TopContributingFeatures)}");
        }

        return 0;
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"L'option '{option}' requiert une valeur.");
        }
        return args[++index];
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Sentinel.ML.Trainer v2.0.0 — Entraînement & évaluation du classifieur PE ML.NET (FastTree)

            UTILISATION :
              Sentinel.ML.Trainer --synthetic [--output <dir>] [--samples <N>] [--seed <S>]
              Sentinel.ML.Trainer --csv <fichier.csv> [--output <dir>] [--max-samples <N>]
              Sentinel.ML.Trainer --ember-jsonl <train_features.jsonl> [--output <dir>] [--max-samples <N>]
              Sentinel.ML.Trainer --inspect <binaire.exe|dll> [--output <dir>]
              Sentinel.ML.Trainer --help

            OPTIONS :
              --synthetic             Entraîne sur le jeu synthétique (tests unitaires / démonstration uniquement).
              --csv <chemin>          Charge un dataset CSV étiqueté (converti localement par l'utilisateur).
              --ember-jsonl <chemin>  Charge directement un fichier JSONL EMBER 2018 obtenu légalement.
              --output, -o <dir>      Dossier de sortie (défaut : %ProgramData%\Sentinel\models).
                                      Produit pe-classifier.zip et pe-classifier.meta.json.
              --version <texte>       Version inscrite dans les métadonnées du modèle.
              --samples <N>           Nombre d'échantillons synthétiques (défaut : 10000).
              --max-samples <N>       Plafond optionnel de lignes lues depuis CSV / EMBER JSONL.
              --seed <S>              Graine aléatoire pour la reproductibilité (défaut : 42).
              --trees <N>             Nombre d'arbres FastTree (défaut : 120).
              --leaves <N>            Nombre max de feuilles par arbre (défaut : 31).
              --learning-rate <R>     Taux d'apprentissage FastTree (défaut : 0.1).
              --test-fraction <F>     Fraction stratifiée réservée à l'évaluation (défaut : 0.2).
              --inspect <chemin>      Extrait les 51 caractéristiques d'un PE et exécute l'inférence si un modèle est présent.
              --help, -h              Affiche cette aide.

            NOTE LÉGALE :
              Ne commitez jamais de fichiers EMBER, de corpus malveillants ni de modèles entraînés dans le dépôt Git.
              Le classifieur ML de SENTINEL est strictement borné (<= 35/100) et n'est jamais seul décisif.
            """);
    }
}
