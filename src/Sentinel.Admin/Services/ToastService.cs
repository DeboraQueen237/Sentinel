namespace Sentinel.Admin.Services;

public enum ToastKind
{
    Info,
    Success,
    Warning,
    Danger
}

public sealed record ToastItem(
    Guid Id,
    ToastKind Kind,
    string Title,
    string Message,
    string? LinkUrl,
    string? LinkLabel,
    DateTimeOffset CreatedAt);

/// <summary>Service de notifications flottantes temps réel par circuit Blazor.</summary>
public sealed class ToastService
{
    private readonly List<ToastItem> _items = new();
    private readonly object _lock = new();

    public IReadOnlyList<ToastItem> Items
    {
        get
        {
            lock (_lock) return _items.ToList();
        }
    }

    public event Action? Changed;

    public void Show(ToastKind kind, string title, string message, string? linkUrl = null, string? linkLabel = null, int durationMs = 5500)
    {
        var item = new ToastItem(Guid.NewGuid(), kind, title, message, linkUrl, linkLabel, DateTimeOffset.UtcNow);
        lock (_lock)
        {
            _items.Insert(0, item);
            if (_items.Count > 5)
            {
                _items.RemoveRange(5, _items.Count - 5);
            }
        }

        Changed?.Invoke();

        if (durationMs > 0)
        {
            _ = AutoDismissAsync(item.Id, durationMs);
        }
    }

    public void Success(string title, string message) => Show(ToastKind.Success, title, message);
    public void Info(string title, string message, string? linkUrl = null, string? linkLabel = null) => Show(ToastKind.Info, title, message, linkUrl, linkLabel);
    public void Warning(string title, string message, string? linkUrl = null, string? linkLabel = null) => Show(ToastKind.Warning, title, message, linkUrl, linkLabel, 7000);
    public void Danger(string title, string message, string? linkUrl = null, string? linkLabel = null) => Show(ToastKind.Danger, title, message, linkUrl, linkLabel, 8500);

    public void Dismiss(Guid id)
    {
        bool removed;
        lock (_lock)
        {
            removed = _items.RemoveAll(x => x.Id == id) > 0;
        }
        if (removed) Changed?.Invoke();
    }

    private async Task AutoDismissAsync(Guid id, int delayMs)
    {
        try
        {
            await Task.Delay(delayMs);
            Dismiss(id);
        }
        catch
        {
            // Ignoré
        }
    }
}
