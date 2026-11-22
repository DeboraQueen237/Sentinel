using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Grpc.Core;
using Grpc.Net.Client;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Security;
using Sentinel.Simulation.Scenarios;

namespace Sentinel.Simulation.Replay;

/// <summary>
/// Rejoue en direct un scénario multi-postes réaliste (trafic bénin + phishing + ransomware + BadUSB
/// + brute force + exfiltration + persistance + ingénierie sociale) vers <c>Sentinel.Server</c> via gRPC
/// (<c>AgentGateway.Register</c>, <c>Heartbeat</c> et <c>SubmitEvents</c>).
/// </summary>
public static class GrpcLiveReplayer
{
    public static async Task<int> RunAsync(CliOptions options, CancellationToken ct = default)
    {
        var url = options.PushGrpcUrl!;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            Console.Error.WriteLine($"[ERREUR] URL gRPC invalide : '{url}'.");
            return 1;
        }

        Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");
        Console.WriteLine($"  SENTINEL — Rejeu gRPC en direct vers {url}");
        Console.WriteLine($"  Mode TLS/mTLS : {(options.NoMtls ? "Désactivé (--no-mtls)" : "mTLS activé (SentinelPki)")}");
        Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");

        X509Certificate2? agentCert = null;
        X509Certificate2? caCert = null;

        try
        {
            var handler = new SocketsHttpHandler
            {
                PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
                EnableMultipleHttp2Connections = true
            };

            if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                if (!options.NoMtls)
                {
                    SentinelPki.EnsureCertificates(options.CertDirectory);
                    agentCert = SentinelPki.LoadAgentCertificate(options.CertDirectory);
                    caCert = SentinelPki.LoadCaCertificate(options.CertDirectory);

                    handler.SslOptions = new SslClientAuthenticationOptions
                    {
                        ClientCertificates = new X509CertificateCollection { agentCert },
                        RemoteCertificateValidationCallback = (_, cert, _, _) => ValidateServerCert(cert, caCert)
                    };
                    Console.WriteLine($"  [PKI] Certificat client mTLS chargé ({agentCert.Subject}).");
                }
                else
                {
                    handler.SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = (_, _, _, _) => true
                    };
                }
            }

            using var channel = GrpcChannel.ForAddress(url, new GrpcChannelOptions
            {
                HttpHandler = handler,
                MaxReceiveMessageSize = 16 * 1024 * 1024,
                MaxSendMessageSize = 16 * 1024 * 1024
            });

            var client = new AgentGateway.AgentGatewayClient(channel);
            var plans = ScenarioCatalog.BuildLiveDemoPlans(options.HostId);

            long batchSeq = 0;
            var totalAccepted = 0;
            var totalRejected = 0;

            foreach (var plan in plans)
            {
                ct.ThrowIfCancellationRequested();
                Console.WriteLine();
                Console.WriteLine($"  ▶ Enregistrement du poste simulé {plan.HostId} ({plan.UserId})...");

                var hello = new AgentHello
                {
                    HostId = plan.HostId,
                    MachineName = plan.MachineName,
                    OsVersion = plan.OsVersion,
                    AgentVersion = "1.0.0-simulation",
                    BinarySha256 = "0000000000000000000000000000000000000000000000000000000000000000"
                };
                hello.Users.Add(plan.UserId);

                var reg = await client.RegisterAsync(hello, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct)
                    .ConfigureAwait(false);

                if (!reg.Accepted)
                {
                    Console.Error.WriteLine($"    [!] Enregistrement refusé pour {plan.HostId} : {reg.Message}");
                    continue;
                }

                Console.WriteLine($"    [OK] Enregistré (config v{reg.SettingsVersion}) — envoi de {plan.Events.Count} événements...");

                // Battement de cœur initial pour passer le poste en statut « En ligne »
                await SendHeartbeatAsync(client, plan.HostId, 0, ct).ConfigureAwait(false);

                var stepDelayMs = options.DelayMs;
                if (stepDelayMs > 0)
                {
                    // Mode démo temps réel : événement par événement avec délai visible sur SignalR
                    for (var i = 0; i < plan.Events.Count; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        var evt = plan.Events[i];
                        var batch = new EventBatch
                        {
                            HostId = plan.HostId,
                            BatchSequence = ++batchSeq
                        };
                        batch.Events.Add(evt.ToProto());

                        var ack = await client.SubmitEventsAsync(batch, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct)
                            .ConfigureAwait(false);

                        totalAccepted += ack.Accepted;
                        totalRejected += ack.Rejected;

                        Console.WriteLine($"      [{i + 1,2}/{plan.Events.Count}] {evt.Category,-12} {evt.EventType,-22} → {Truncate(evt.Subject, 48)}");

                        if (i + 1 < plan.Events.Count)
                        {
                            await Task.Delay(stepDelayMs, ct).ConfigureAwait(false);
                        }
                    }
                }
                else
                {
                    // Mode rapide par petits lots chronologiques
                    const int chunkSize = 5;
                    for (var i = 0; i < plan.Events.Count; i += chunkSize)
                    {
                        ct.ThrowIfCancellationRequested();
                        var batch = new EventBatch
                        {
                            HostId = plan.HostId,
                            BatchSequence = ++batchSeq
                        };

                        var end = Math.Min(plan.Events.Count, i + chunkSize);
                        for (var j = i; j < end; j++)
                        {
                            batch.Events.Add(plan.Events[j].ToProto());
                        }

                        var ack = await client.SubmitEventsAsync(batch, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct)
                            .ConfigureAwait(false);

                        totalAccepted += ack.Accepted;
                        totalRejected += ack.Rejected;
                    }
                }

                await SendHeartbeatAsync(client, plan.HostId, plan.Events.Count, ct).ConfigureAwait(false);
                Console.WriteLine($"    [OK] {plan.HostId} terminé ({plan.Events.Count} événements soumis).");
            }

            Console.WriteLine();
            Console.WriteLine($"  ✔ Rejeu gRPC terminé : {totalAccepted} événement(s) accepté(s), {totalRejected} rejeté(s) sur {plans.Count} poste(s).");
            return totalRejected > 0 && totalAccepted == 0 ? 1 : 0;
        }
        catch (RpcException ex)
        {
            Console.Error.WriteLine($"[ERREUR gRPC] ({ex.StatusCode}) {ex.Status.Detail}");
            Console.Error.WriteLine("  Vérifiez que Sentinel.Server est démarré et que les certificats mTLS correspondent (ou essayez --no-mtls).");
            return 2;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"[ERREUR] Impossible de pousser les événements vers {url} : {ex.Message}");
            return 2;
        }
        finally
        {
            agentCert?.Dispose();
            caCert?.Dispose();
        }
    }

    private static async Task SendHeartbeatAsync(
        AgentGateway.AgentGatewayClient client,
        string hostId,
        long eventsCollected,
        CancellationToken ct)
    {
        var hb = new HeartbeatRequest
        {
            HostId = hostId,
            CpuPercent = 1.4,
            WorkingSetBytes = 64 * 1024 * 1024,
            QueueLength = 0,
            EventsCollected = eventsCollected,
            SettingsVersion = 1
        };

        string[] collectorNames = ["Process", "Network", "Clipboard", "FileSystem", "Session", "Device", "Browser", "Typing"];
        foreach (var name in collectorNames)
        {
            hb.Collectors.Add(new CollectorStatus
            {
                Name = name,
                Running = true,
                EventsProduced = eventsCollected / collectorNames.Length
            });
        }

        try
        {
            await client.HeartbeatAsync(hb, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct)
                .ConfigureAwait(false);
        }
        catch
        {
            // Le heartbeat reste informatif pour la démo.
        }
    }

    private static bool ValidateServerCert(X509Certificate? cert, X509Certificate2 caCert)
    {
        if (cert is null) return false;
        if (cert is X509Certificate2 c2) return SentinelPki.ValidateIssuedBy(c2, caCert);
        using var copy = new X509Certificate2(cert);
        return SentinelPki.ValidateIssuedBy(copy, caCert);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 1)] + "…";
}
