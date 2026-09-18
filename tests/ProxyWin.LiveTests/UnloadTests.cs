using System.Diagnostics;
using System.Windows.Automation;
using ProxyWin.Core;
using ProxyWin.Windows;

internal static class UnloadTests
{
    public static async Task<int> Run(string appPath, string directory)
    {
        Directory.CreateDirectory(directory);
        using var report = new StreamWriter(Path.Combine(directory, "result.txt")) { AutoFlush = true };
        Console.SetOut(report); Console.SetError(report);
        var children = new List<Process>();
        using var watchdog = new Timer(_ => { foreach (var child in children) try { if (!child.HasExited) child.Kill(); } catch (InvalidOperationException) { } Environment.Exit(124); }, null, TimeSpan.FromSeconds(120), Timeout.InfiniteTimeSpan);
        try
        {
            var initial = await DriverService.TryUnloadAsync();
            Require(initial.Unloaded, "Cannot start an exclusive unload test: " + initial.Message);
            Require(DriverService.IsStopped(), "Initial service state");
            var profile = new Profile { Rules = [new RoutingRule { Name = "Unload fixture", Destinations = "203.0.113.10", Ports = "18081", Action = RuleAction.Block, ProcessName = "not-a-running-process.exe" }] };
            await using (var otherClient = new DivertEngine())
            {
                await otherClient.StartAsync(profile);
                var retained = await DriverService.TryUnloadAsync();
                Require(!retained.Unloaded && !DriverService.IsStopped() && otherClient.IsRunning, "Active client must be preserved");
                Console.WriteLine("PASS active capture prevents shared-service unload: " + retained.Message);
                await otherClient.StopAsync();
            }
            Require((await DriverService.TryUnloadAsync()).Unloaded && DriverService.IsStopped(), "Idle driver unload");
            Console.WriteLine("PASS idle service unload, confirmed STOPPED/absent");
            var storeDirectory = Path.Combine(directory, "profile");
            new ProfileStore(storeDirectory).Save(profile);
            for (var mode = 0; mode < 3; mode++)
            {
                var cleanupReport = Path.Combine(storeDirectory, "driver-cleanup.txt");
                if (File.Exists(cleanupReport)) File.Delete(cleanupReport);
                var start = new ProcessStartInfo(appPath) { UseShellExecute = false };
                start.ArgumentList.Add("--driver-fixture"); start.ArgumentList.Add(storeDirectory);
                var child = Process.Start(start)!; children.Add(child);
                await Wait.Until(() => { child.Refresh(); return child.MainWindowHandle != IntPtr.Zero; }, "GUI opened", 20);
                var window = AutomationElement.FromHandle(child.MainWindowHandle);
                if (mode == 2)
                {
                    ((InvokePattern)Find(window, "ToggleButton").GetCurrentPattern(InvokePattern.Pattern)).Invoke();
                    // UI Automation queues Invoke. Wait until Apply has actually
                    // entered its handler before testing close-during-start.
                    await Wait.Until(() => Text(window, "StatusText").Contains("Working") || Text(window, "StatusText").Contains("Active"), "Apply dispatched");
                    var phase = Text(window, "StatusText");
                    Require(child.CloseMainWindow(), "Close immediately after Apply");
                    await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
                    await Wait.Until(() => File.Exists(cleanupReport) && DriverService.IsStopped(), "Startup-close cleanup guard", 15);
                    Console.WriteLine($"PASS close after Apply dispatch ({phase}): no late reopen, cleanup completed, service STOPPED/absent");
                    continue;
                }
                for (var cycle = 0; cycle < 3; cycle++)
                {
                    await Click(window, "ToggleButton");
                    await Wait.Until(() => Text(window, "StatusText").Contains("Active") && !DriverService.IsStopped(), "Apply reloads driver", 20);
                    await Click(window, "ToggleButton");
                    await Wait.Until(() => Text(window, "StatusText").Contains("Stopped") && DriverService.IsStopped(), "Stop unloads driver", 20);
                }
                await Click(window, "ToggleButton");
                await Wait.Until(() => Text(window, "StatusText").Contains("Active"), "Active before monitoring");
                await Click(window, "ObserveButton");
                await Wait.Until(() => Text(window, "ObserveButton").Contains("Stop monitor"), "Monitor active");
                await Click(window, "ToggleButton");
                await Wait.Until(() => Text(window, "StatusText").Contains("Stopped"), "Routing stopped");
                Require(!DriverService.IsStopped(), "Monitor keeps shared driver loaded");
                await Click(window, "ObserveButton");
                await Wait.Until(DriverService.IsStopped, "Last monitor stop unloads driver");
                await Click(window, "ToggleButton"); await Wait.Until(() => Text(window, "StatusText").Contains("Active"), "Active before exit");
                var watch = Stopwatch.StartNew();
                if (mode == 0) Require(child.CloseMainWindow(), "Normal window close"); else child.Kill();
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
                await Wait.Until(() => File.Exists(cleanupReport) && new FileInfo(cleanupReport).Length != 0 && DriverService.IsStopped(), "Guard completion and kernel service stopped", 15);
                Console.WriteLine($"PASS {(mode == 0 ? "X/WM_CLOSE" : "TerminateProcess")}: service STOPPED/absent, guard report after {watch.Elapsed.TotalMilliseconds:F1} ms; {File.ReadAllText(cleanupReport).Trim()}");
            }
            Require(DriverService.IsStopped(), "Final service state");
            Console.WriteLine("PASS six Apply/Stop unload/reload cycles, monitor retention, normal/forced exit; final shared driver STOPPED/absent");
            return 0;
        }
        catch (Exception ex) { Console.WriteLine("FAIL " + ex); return 1; }
        finally
        {
            foreach (var child in children) { if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); } child.Dispose(); }
        }
    }
    private static AutomationElement Find(AutomationElement window, string id) => window.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.AutomationIdProperty, id)) ?? throw new Exception("Missing " + id);
    private static string Text(AutomationElement window, string id) => Find(window, id).Current.Name;
    private static async Task Click(AutomationElement window, string id)
    {
        await Wait.Until(() => Find(window, id).Current.IsEnabled, "Button enabled: " + id, 20);
        ((InvokePattern)Find(window, id).GetCurrentPattern(InvokePattern.Pattern)).Invoke(); await Task.Delay(50);
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
