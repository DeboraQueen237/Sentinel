using Sentinel.Shared.Models;

namespace Sentinel.Storage.Entities;

/// <summary>
/// Ticket d'action de réponse graduée et réversible (doc §9.2–§9.3, exigence F7).
/// Stocke l'état initial (<see cref="RevertStateJson"/>) permettant l'annulation en un clic.
/// </summary>
public sealed class ActionTicketEntity
{
    public Guid Id { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public long CreatedAtUnixMs { get; set; }

    public DateTimeOffset? ExecutedAt { get; set; }

    public DateTimeOffset? RevertedAt { get; set; }

    public string HostId { get; set; } = string.Empty;

    public Guid? AlertId { get; set; }

    /// <summary>Valeur entière de <see cref="ResponseActionType"/>.</summary>
    public int ActionType { get; set; }

    public string Target { get; set; } = string.Empty;

    public string ParametersJson { get; set; } = "{}";

    public ActionStatus Status { get; set; }

    public bool Automatic { get; set; }

    public bool Reversible { get; set; } = true;

    public string Rationale { get; set; } = string.Empty;

    public string? ResultMessage { get; set; }

    public string? RevertStateJson { get; set; }
}
