using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Globalization;
using ProxyWin.Windows;

namespace ProxyWin.App;

public partial class App : Application
{
    private Mutex? instance;
    protected override async void OnStartup(StartupEventArgs e)
    {
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
        CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.CurrentUICulture;
        base.OnStartup(e);
        if (e.Args is ["--picker-test", var pickerReport])
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(pickerReport))!;
            Directory.CreateDirectory(directory);
            try
            {
                var test = new MainWindow(new ProfileStore(Path.Combine(directory, "isolated-profile")), smokeMode: true);
                MainWindow = test; test.Show();
                await test.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                await test.VerifyProcessCaretAsync();
                File.WriteAllText(pickerReport, "PASS: WPF process typing preserves text, caret and selection."); Shutdown(0);
            }
            catch (Exception ex) { File.WriteAllText(pickerReport, ex.ToString()); Shutdown(1); }
            return;
        }
        if (e.Args is ["--smoke-test", var output])
        {
            try
            {
                Directory.CreateDirectory(output);
                File.WriteAllText(Path.Combine(output, "result.txt"), "RUNNING");
                DispatcherUnhandledException += (_, error) =>
                {
                    File.WriteAllText(Path.Combine(output, "result.txt"), error.Exception.ToString());
                    error.Handled = true;
                    Shutdown(1);
                };
                var smoke = new MainWindow(new ProfileStore(Path.Combine(output, "isolated-profile")), smokeMode: true);
                MainWindow = smoke;
                smoke.Show();
                await smoke.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(smoke, Path.Combine(output, "main.png"));
                smoke.VerifySmokeBindings();
                await smoke.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(smoke, Path.Combine(output, "main-populated.png"));
                smoke.Width = smoke.MinWidth; smoke.Height = smoke.MinHeight;
                await smoke.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(smoke, Path.Combine(output, "main-compact.png"));
                var proxy = new ProxyDialog(null) { Owner = smoke };
                proxy.Show();
                await proxy.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(proxy, Path.Combine(output, "proxy-editor.png"));
                proxy.Close();
                var rule = new RuleDialog(null, []) { Owner = smoke };
                rule.Show();
                await rule.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(rule, Path.Combine(output, "rule-editor.png"));
                rule.Close();
                File.WriteAllText(Path.Combine(output, "result.txt"), "PASS: English compact/minimum window and editors, DIRECT/PROXY/BLOCK and process-wide wildcard quick-add, rule order/toggle, observation-to-rule, duplicate prevention, substring process search preserving manual names, and loaded app icon; no driver opened; no user profile modified.");
                Shutdown(0);
            }
            catch (Exception ex) { File.WriteAllText(Path.Combine(output, "result.txt"), ex.ToString()); Shutdown(1); }
            return;
        }
        instance = new Mutex(true, "Local\\ProxyWin.GUI", out var created);
        if (!created) { AppMessages.Info(null, "ProxyWin is already running."); Shutdown(); return; }
        var window = new MainWindow(new ProfileStore(ProfileStore.DefaultDirectory));
        MainWindow = window;
        window.Show();
    }

    private static void Capture(Window window, string path)
    {
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path);
        encoder.Save(file);
    }

    protected override void OnExit(ExitEventArgs e) { instance?.Dispose(); base.OnExit(e); }
    private void OpenHelp(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { ToolTip: string text } button) return;
        var tip = new ToolTip { Content = text, PlacementTarget = button, Placement = PlacementMode.Bottom, StaysOpen = false };
        tip.IsOpen = true;
    }
}
