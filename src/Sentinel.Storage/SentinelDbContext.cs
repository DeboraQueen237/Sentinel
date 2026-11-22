using Microsoft.EntityFrameworkCore;
using Sentinel.Storage.Entities;

namespace Sentinel.Storage;

/// <summary>
/// Contexte Entity Framework Core de SENTINEL (SQLite par défaut, compatible PostgreSQL).
/// </summary>
public sealed class SentinelDbContext : DbContext
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options) : base(options)
    {
    }

    public DbSet<EventEntity> Events => Set<EventEntity>();
    public DbSet<ClusterEntity> Clusters => Set<ClusterEntity>();
    public DbSet<ClusterLinkEntity> ClusterLinks => Set<ClusterLinkEntity>();
    public DbSet<AlertEntity> Alerts => Set<AlertEntity>();
    public DbSet<AlertEventEntity> AlertEvents => Set<AlertEventEntity>();
    public DbSet<AlertHistoryEntity> AlertHistory => Set<AlertHistoryEntity>();
    public DbSet<ActionTicketEntity> ActionTickets => Set<ActionTicketEntity>();
    public DbSet<HostEntity> Hosts => Set<HostEntity>();
    public DbSet<SettingsEntity> Settings => Set<SettingsEntity>();
    public DbSet<BaselineSnapshotEntity> BaselineSnapshots => Set<BaselineSnapshotEntity>();
    public DbSet<AdminUserEntity> AdminUsers => Set<AdminUserEntity>();
    public DbSet<AdminSessionEntity> AdminSessions => Set<AdminSessionEntity>();
    public DbSet<AuditEntryEntity> AuditEntries => Set<AuditEntryEntity>();
    public DbSet<EvaluationMetricEntity> EvaluationMetrics => Set<EvaluationMetricEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<EventEntity>(e =>
        {
            e.ToTable("Events");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.HostId).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserId).HasMaxLength(256).IsRequired();
            e.Property(x => x.EventType).HasMaxLength(128).IsRequired();
            e.Property(x => x.Subject).HasMaxLength(2048).IsRequired();
            e.Property(x => x.AttributesJson).IsRequired();
            e.Property(x => x.CorrelationHints).HasMaxLength(2048);
            e.Property(x => x.Justification).IsRequired();
            e.Property(x => x.MatchedRulesJson).IsRequired();
            e.Property(x => x.MitreTechniquesJson).IsRequired();
            e.Property(x => x.ChainSeq).ValueGeneratedNever();
            e.Property(x => x.Hash).HasMaxLength(64).IsRequired();
            e.Property(x => x.PreviousHash).HasMaxLength(64).IsRequired();

            e.HasIndex(x => x.ChainSeq).IsUnique();
            e.HasIndex(x => x.TimestampUnixMs);
            e.HasIndex(x => new { x.HostId, x.TimestampUnixMs });
            e.HasIndex(x => new { x.Category, x.TimestampUnixMs });
            e.HasIndex(x => new { x.Score, x.TimestampUnixMs });
            e.HasIndex(x => x.ClusterId);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.Level);
        });

        modelBuilder.Entity<ClusterEntity>(e =>
        {
            e.ToTable("Clusters");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.HostId).HasMaxLength(128).IsRequired();
            e.Property(x => x.ChainId).HasMaxLength(128);
            e.Property(x => x.ChainName).HasMaxLength(256);
            e.Property(x => x.ContextKeysJson).IsRequired();
            e.Property(x => x.MitreTechniquesJson).IsRequired();
            e.Property(x => x.Justification).IsRequired();

            e.HasIndex(x => x.LastSeenUnixMs);
            e.HasIndex(x => new { x.HostId, x.LastSeenUnixMs });
            e.HasIndex(x => x.Score);

            e.HasMany(x => x.Links)
                .WithOne(l => l.Cluster)
                .HasForeignKey(l => l.ClusterId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ClusterLinkEntity>(e =>
        {
            e.ToTable("ClusterLinks");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Key).HasMaxLength(512).IsRequired();

            e.HasIndex(x => x.ClusterId);
            e.HasIndex(x => x.FromEventId);
            e.HasIndex(x => x.ToEventId);
        });

        modelBuilder.Entity<AlertEntity>(e =>
        {
            e.ToTable("Alerts");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.HostId).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserId).HasMaxLength(256).IsRequired();
            e.Property(x => x.Title).HasMaxLength(512).IsRequired();
            e.Property(x => x.Summary).IsRequired();
            e.Property(x => x.Justification).IsRequired();
            e.Property(x => x.MitreTechniquesJson).IsRequired();

            e.HasIndex(x => x.CreatedAtUnixMs);
            e.HasIndex(x => x.UpdatedAtUnixMs);
            e.HasIndex(x => new { x.Status, x.CreatedAtUnixMs });
            e.HasIndex(x => new { x.HostId, x.CreatedAtUnixMs });
            e.HasIndex(x => x.Level);
            e.HasIndex(x => x.ThreatType);
            e.HasIndex(x => x.ClusterId);

            e.HasMany(x => x.AlertEvents)
                .WithOne(ae => ae.Alert)
                .HasForeignKey(ae => ae.AlertId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(x => x.History)
                .WithOne(h => h.Alert)
                .HasForeignKey(h => h.AlertId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AlertEventEntity>(e =>
        {
            e.ToTable("AlertEvents");
            e.HasKey(x => new { x.AlertId, x.EventId });
            e.HasIndex(x => x.EventId);
        });

        modelBuilder.Entity<AlertHistoryEntity>(e =>
        {
            e.ToTable("AlertHistory");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Actor).HasMaxLength(128).IsRequired();
            e.Property(x => x.Action).HasMaxLength(128).IsRequired();
            e.Property(x => x.Comment).HasMaxLength(2048);

            e.HasIndex(x => x.AlertId);
        });

        modelBuilder.Entity<ActionTicketEntity>(e =>
        {
            e.ToTable("ActionTickets");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.HostId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Target).HasMaxLength(2048).IsRequired();
            e.Property(x => x.ParametersJson).IsRequired();
            e.Property(x => x.Rationale).IsRequired();
            e.Property(x => x.ResultMessage).HasMaxLength(2048);

            e.HasIndex(x => x.CreatedAtUnixMs);
            e.HasIndex(x => new { x.Status, x.CreatedAtUnixMs });
            e.HasIndex(x => new { x.HostId, x.Status });
            e.HasIndex(x => x.AlertId);
        });

        modelBuilder.Entity<HostEntity>(e =>
        {
            e.ToTable("Hosts");
            e.HasKey(x => x.HostId);
            e.Property(x => x.HostId).HasMaxLength(128).ValueGeneratedNever();
            e.Property(x => x.MachineName).HasMaxLength(256).IsRequired();
            e.Property(x => x.OsVersion).HasMaxLength(256).IsRequired();
            e.Property(x => x.AgentVersion).HasMaxLength(64).IsRequired();
            e.Property(x => x.BinarySha256).HasMaxLength(64).IsRequired();
            e.Property(x => x.UsersJson).IsRequired();
            e.Property(x => x.CollectorsJson).IsRequired();

            e.HasIndex(x => x.LastSeenUnixMs);
        });

        modelBuilder.Entity<SettingsEntity>(e =>
        {
            e.ToTable("Settings");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.SettingsJson).IsRequired();
        });

        modelBuilder.Entity<BaselineSnapshotEntity>(e =>
        {
            e.ToTable("BaselineSnapshots");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.SnapshotJson).IsRequired();
        });

        modelBuilder.Entity<AdminUserEntity>(e =>
        {
            e.ToTable("AdminUsers");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Username).HasMaxLength(128).IsRequired();
            e.Property(x => x.PasswordHash).HasMaxLength(256).IsRequired();
            e.Property(x => x.PasswordSalt).HasMaxLength(256).IsRequired();
            e.Property(x => x.TotpSecretProtected).IsRequired();

            e.HasIndex(x => x.Username).IsUnique();
        });

        modelBuilder.Entity<AdminSessionEntity>(e =>
        {
            e.ToTable("AdminSessions");
            e.HasKey(x => x.TokenHash);
            e.Property(x => x.TokenHash).HasMaxLength(64).ValueGeneratedNever();
            e.Property(x => x.Username).HasMaxLength(128).IsRequired();
            e.Property(x => x.IpAddress).HasMaxLength(64);

            e.HasIndex(x => x.Username);
        });

        modelBuilder.Entity<AuditEntryEntity>(e =>
        {
            e.ToTable("AuditEntries");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Actor).HasMaxLength(128).IsRequired();
            e.Property(x => x.Action).HasMaxLength(128).IsRequired();
            e.Property(x => x.Target).HasMaxLength(512).IsRequired();
            e.Property(x => x.Details).HasMaxLength(4096);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.Hash).HasMaxLength(64).IsRequired();
            e.Property(x => x.PreviousHash).HasMaxLength(64).IsRequired();

            e.HasIndex(x => x.TimestampUnixMs);
            e.HasIndex(x => new { x.Actor, x.TimestampUnixMs });
            e.HasIndex(x => new { x.Action, x.TimestampUnixMs });
        });

        modelBuilder.Entity<EvaluationMetricEntity>(e =>
        {
            e.ToTable("EvaluationMetrics");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Scenario).HasMaxLength(256).IsRequired();
            e.Property(x => x.Configuration).HasMaxLength(64).IsRequired();

            e.HasIndex(x => new { x.Scenario, x.Configuration });
        });
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        SynchronizeUnixTimestamps();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        SynchronizeUnixTimestamps();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    /// <summary>
    /// Maintient automatiquement la cohérence des colonnes <c>*UnixMs</c> avec leurs champs <see cref="DateTimeOffset"/>.
    /// </summary>
    private void SynchronizeUnixTimestamps()
    {
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified))
                continue;

            switch (entry.Entity)
            {
                case EventEntity e:
                    e.TimestampUnixMs = ResolveUnixMs(e.Timestamp, e.TimestampUnixMs);
                    if (e.Timestamp == default && e.TimestampUnixMs != 0)
                        e.Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(e.TimestampUnixMs);
                    break;
                case ClusterEntity c:
                    c.FirstSeenUnixMs = ResolveUnixMs(c.FirstSeen, c.FirstSeenUnixMs);
                    if (c.FirstSeen == default && c.FirstSeenUnixMs != 0)
                        c.FirstSeen = DateTimeOffset.FromUnixTimeMilliseconds(c.FirstSeenUnixMs);
                    c.LastSeenUnixMs = ResolveUnixMs(c.LastSeen, c.LastSeenUnixMs);
                    if (c.LastSeen == default && c.LastSeenUnixMs != 0)
                        c.LastSeen = DateTimeOffset.FromUnixTimeMilliseconds(c.LastSeenUnixMs);
                    break;
                case AlertEntity a:
                    a.CreatedAtUnixMs = ResolveUnixMs(a.CreatedAt, a.CreatedAtUnixMs);
                    if (a.CreatedAt == default && a.CreatedAtUnixMs != 0)
                        a.CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(a.CreatedAtUnixMs);
                    a.UpdatedAtUnixMs = ResolveUnixMs(a.UpdatedAt, a.UpdatedAtUnixMs);
                    if (a.UpdatedAt == default && a.UpdatedAtUnixMs != 0)
                        a.UpdatedAt = DateTimeOffset.FromUnixTimeMilliseconds(a.UpdatedAtUnixMs);
                    break;
                case ActionTicketEntity t:
                    t.CreatedAtUnixMs = ResolveUnixMs(t.CreatedAt, t.CreatedAtUnixMs);
                    if (t.CreatedAt == default && t.CreatedAtUnixMs != 0)
                        t.CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(t.CreatedAtUnixMs);
                    break;
                case HostEntity h:
                    h.LastSeenUnixMs = ResolveUnixMs(h.LastSeen, h.LastSeenUnixMs);
                    if (h.LastSeen == default && h.LastSeenUnixMs != 0)
                        h.LastSeen = DateTimeOffset.FromUnixTimeMilliseconds(h.LastSeenUnixMs);
                    break;
                case AuditEntryEntity au:
                    au.TimestampUnixMs = ResolveUnixMs(au.Timestamp, au.TimestampUnixMs);
                    if (au.Timestamp == default && au.TimestampUnixMs != 0)
                        au.Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(au.TimestampUnixMs);
                    break;
            }
        }
    }

    private static long ResolveUnixMs(DateTimeOffset dto, long currentMs) =>
        dto != default ? dto.ToUnixTimeMilliseconds() : currentMs;
}
