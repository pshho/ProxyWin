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
        SocketException socket => $"네트워크 오류: {socket.SocketErrorCode}.",
        Win32Exception native => $"Windows 오류 {native.NativeErrorCode}. " + (native.NativeErrorCode switch
        {
            5 => "관리자 권한으로 실행하세요(ProxyWin.exe 우클릭 → 관리자 권한으로 실행).", 2 or 3 => "압축을 풀 때 driver 폴더를 포함한 배포 폴더 전체를 함께 두세요.",
            13 => "설정 파일과 드라이버 파일을 확인하세요.", 577 or 1275 => "Windows가 드라이버 로드를 막았습니다. 드라이버 서명과 보안 프로그램 설정을 확인하세요.",
            _ => "권한과 드라이버 파일을 확인하세요."
        }),
        OperationCanceledException => "취소되었거나 시간이 초과되었습니다.",
        UnauthorizedAccessException => "접근이 거부되었습니다. 파일 권한을 확인하세요.",
        System.IO.IOException io when io.TargetSite?.DeclaringType?.Namespace?.StartsWith("System", StringComparison.Ordinal) == true
            => $"입출력 오류({io.HResult & 0xffff}). 파일과 네트워크 연결을 확인하세요.",
        _ => error.Message
    };

    private static bool Show(Window? owner, string message, string title, bool confirm)
    {
        var window = new Window
        {
            Title = title, Width = 440, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false, Style = (Style)Application.Current.FindResource(typeof(Window))
        };
        if (owner is not null) window.Owner = owner;
        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, MaxHeight = 280, LineHeight = 18 });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        if (confirm) buttons.Children.Add(new Button { Content = "취소", IsCancel = true, Margin = new Thickness(0, 0, 6, 0) });
        var accept = new Button { Content = confirm ? "삭제" : "확인", IsDefault = true, MinWidth = 72, Style = (Style)Application.Current.FindResource("Primary") };
        accept.Click += (_, _) => window.DialogResult = true;
        buttons.Children.Add(accept); panel.Children.Add(buttons); window.Content = panel;
        return window.ShowDialog() == true;
    }
}
