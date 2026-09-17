using System.ComponentModel;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;

namespace ProxyWin.App;

internal static class AppMessages
{
    public static void Error(Window owner, Exception error) => Show(owner, Describe(error), "ProxyWin", false);
    public static void Info(Window? owner, string message) => Show(owner, message, "ProxyWin", false);
    public static bool Confirm(Window owner, string message, string title) => Show(owner, message, title, true);
    internal static string Describe(Exception error) => error switch
    {
        SocketException socket => $"Network error: {socket.SocketErrorCode}.",
        Win32Exception native => $"Windows error {native.NativeErrorCode}. " + (native.NativeErrorCode switch
        {
            5 => "Run ProxyWin as administrator.", 2 or 3 => "Keep the full release folder intact.",
            13 => "Check the profile and driver files.", 577 or 1275 => "Windows blocked the driver. Check its signature and security settings.",
            _ => "Check permissions and driver availability."
        }),
        OperationCanceledException => "Cancelled or timed out.",
        UnauthorizedAccessException => "Access denied. Check file permissions.",
        System.IO.IOException io when io.TargetSite?.DeclaringType?.Namespace?.StartsWith("System", StringComparison.Ordinal) == true
            => $"I/O error ({io.HResult & 0xffff}). Check the file and network connection.",
        _ => error.Message
    };

    private static bool Show(Window? owner, string message, string title, bool confirm)
    {
        var window = new Window
        {
            Title = title, Width = 410, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false, Style = (Style)Application.Current.FindResource(typeof(Window))
        };
        if (owner is not null) window.Owner = owner;
        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, MaxHeight = 240 });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        if (confirm) buttons.Children.Add(new Button { Content = "Cancel", IsCancel = true, Margin = new Thickness(0, 0, 6, 0) });
        var accept = new Button { Content = confirm ? "Remove" : "OK", IsDefault = true, Style = (Style)Application.Current.FindResource("Primary") };
        accept.Click += (_, _) => window.DialogResult = true;
        buttons.Children.Add(accept); panel.Children.Add(buttons); window.Content = panel;
        return window.ShowDialog() == true;
    }
}
