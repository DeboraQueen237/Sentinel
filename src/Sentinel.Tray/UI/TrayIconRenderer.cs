using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace Sentinel.Tray.UI;

public enum TrayVisualState
{
    Disconnected,
    Active,
    LearningOrWarning,
    Critical
}

/// <summary>Dessine une icône vectorielle GDI+ en forme de bouclier selon l'état de protection SENTINEL.</summary>
public static class TrayIconRenderer
{
    public static Icon CreateShieldIcon(TrayVisualState state)
    {
        var (fill, border, accent) = state switch
        {
            TrayVisualState.Active => (Color.FromArgb(16, 185, 129), Color.FromArgb(6, 95, 70), Color.White),
            TrayVisualState.LearningOrWarning => (Color.FromArgb(245, 158, 11), Color.FromArgb(146, 64, 14), Color.White),
            TrayVisualState.Critical => (Color.FromArgb(239, 68, 68), Color.FromArgb(127, 29, 29), Color.White),
            _ => (Color.FromArgb(100, 116, 139), Color.FromArgb(51, 65, 85), Color.FromArgb(226, 232, 240))
        };

        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var path = new GraphicsPath();
            path.AddPolygon([
                new PointF(16, 2),
                new PointF(28, 6.5f),
                new PointF(27, 17.5f),
                new PointF(16, 30),
                new PointF(5, 17.5f),
                new PointF(4, 6.5f)
            ]);

            using var brush = new SolidBrush(fill);
            using var pen = new Pen(border, 2f);
            g.FillPath(brush, path);
            g.DrawPath(pen, path);

            // Lettre S / coche centrale
            using var font = new Font("Segoe UI", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
            using var textBrush = new SolidBrush(accent);
            var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("S", font, textBrush, new RectangleF(0, 1, 32, 29), sf);
        }

        var hIcon = bmp.GetHicon();
        try
        {
            using var temp = Icon.FromHandle(hIcon);
            return (Icon)temp.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
