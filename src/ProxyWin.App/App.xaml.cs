using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Globalization;
using ProxyWin.Core;
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
        if (e.Args is ["--driver-cleanup", var parentId, var parentStarted, var readyEvent, var cleanupReport])
        {
            Shutdown(await DriverCleanupGuard.RunAsync(parentId, parentStarted, readyEvent, cleanupReport));
            return;
        }
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
                // Deterministic DNS answers keep CI offline and preserve loopback rejection.
                static async Task<string> ResolveFixture(string value, CancellationToken ct)
                {
                    if (value != "fixture.example, 203.0.113.10") return await DestinationResolver.ResolveAsync(value, ct);
                    await Task.Delay(25, ct);
                    return "203.0.113.11, 203.0.113.10";
                }
                var smoke = new MainWindow(new ProfileStore(Path.Combine(output, "isolated-profile")), smokeMode: true, ResolveFixture);
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
                var statusPreview = (TextBlock)smoke.FindName("StatusText");
                var togglePreview = (Button)smoke.FindName("ToggleButton");
                var originalStatus = statusPreview.Text; var originalToggle = togglePreview.Content;
                foreach (var (status, label, file) in new[] { ("● Active", "■ Stop", "status-active.png"), ("● Working", "Working…", "status-working.png") })
                {
                    statusPreview.Text = status; togglePreview.Content = label;
                    await smoke.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                    Capture(smoke, Path.Combine(output, file));
                }
                statusPreview.Text = originalStatus; togglePreview.Content = originalToggle;
                var eventsPreview = (Expander)smoke.FindName("EventsPanel");
                eventsPreview.IsExpanded = true;
                await smoke.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                Capture(smoke, Path.Combine(output, "main-events-expanded.png"));
                eventsPreview.IsExpanded = false;
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
                var edited = new RuleDialog(new RoutingRule { Destinations = "203.0.113.10", Ports = "80", Action = RuleAction.Direct }, []) { Owner = smoke };
                edited.ContentRendered += async (_, _) =>
                {
                    ((TextBox)edited.FindName("DestinationsBox")).Text = "203.0.113.10, 198.51.100.20";
                    ((TextBox)edited.FindName("PortsBox")).Text = "80, 443, 8000-9000";
                    await edited.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                    Capture(edited, Path.Combine(output, "rule-editor-multiple.png"));
                    ((Button)edited.FindName("SaveButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                };
                if (edited.ShowDialog() != true || edited.Result?.Destinations != "203.0.113.10, 198.51.100.20"
                    || edited.Result.Ports != "80, 443, 8000-9000") throw new InvalidOperationException("Comma-separated rule editing failed.");
                await smoke.VerifyDomainBindingsAsync();
                var domainEditor = new RuleDialog(new RoutingRule { Destinations = "fixture.example, 203.0.113.10", Action = RuleAction.Direct }, [], ResolveFixture) { Owner = smoke };
                domainEditor.ContentRendered += (_, _) => ((Button)domainEditor.FindName("SaveButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (domainEditor.ShowDialog() != true || domainEditor.Result is null || domainEditor.Result.Destinations.Contains("fixture.example")
                    || RuleParser.Networks(domainEditor.Result.Destinations).Length < 2) throw new InvalidOperationException("Domain editor save failed.");
                File.WriteAllText(Path.Combine(output, "result.txt"), "PASS: English compact/minimum window and editors, comma-separated rule addition and editing, domain conversion in quick-add and rule editor (injected DNS fixture), update notification/current-version states, DIRECT/PROXY/BLOCK and process-wide wildcard quick-add, rule order/toggle, observation-to-rule, duplicate prevention, substring process search preserving manual names, and loaded app icon; no driver opened; no user profile modified.");
                Shutdown(0);
            }
            catch (Exception ex) { File.WriteAllText(Path.Combine(output, "result.txt"), ex.ToString()); Shutdown(1); }
            return;
        }
        if (e.Args is ["--driver-fixture", var fixtureDirectory])
        {
            // Explicit opt-in for the elevated integration harness; never use the user's profile.
            var fixture = new MainWindow(new ProfileStore(Path.GetFullPath(fixtureDirectory)));
            fixture.Title = "ProxyWin driver test";
            MainWindow = fixture; fixture.Show();
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
        if (window is MainWindow main)
        {
            var measurements = new[] { "EditorPanel", "RulesGrid", "ObservationGrid", "EventsPanel" }
                .ToDictionary(name => name, name => new { Width = ((FrameworkElement)main.FindName(name)).ActualWidth, Height = ((FrameworkElement)main.FindName(name)).ActualHeight });
            File.WriteAllText(Path.ChangeExtension(path, ".layout.json"), System.Text.Json.JsonSerializer.Serialize(measurements));
        }
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
