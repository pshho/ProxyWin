global using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Windows.Automation;
using ProxyWin.Core;
using ProxyWin.Windows;

if (args is ["--unload", var unloadApp, var unloadDirectory]) return await UnloadTests.Run(unloadApp, unloadDirectory);

if (args is not [var appExe, var whaleExe, var outputDirectory, var soakText])
{
    Console.Error.WriteLine("Usage: ProxyWin.LiveTests <ProxyWin.exe> <whale.exe> <output-directory> <soak-seconds>");
    return 2;
}
Directory.CreateDirectory(outputDirectory);
using var report = new StreamWriter(Path.Combine(outputDirectory, "result.txt")) { AutoFlush = true };
Console.SetOut(report); Console.SetError(report);
var children = new List<Process>();
using var watchdog = new Timer(_ =>
{
    Console.WriteLine("FAIL watchdog expired");
    lock (children) foreach (var child in children) try { if (!child.HasExited) child.Kill(true); } catch (InvalidOperationException) { }
    Environment.Exit(124);
}, null, TimeSpan.FromSeconds(int.Parse(soakText) + 300), Timeout.InfiniteTimeSpan);
var profilePath = Path.Combine(ProfileStore.DefaultDirectory, "profile.dat");
string? ProfileHash() => File.Exists(profilePath) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(profilePath))) : null;
var profileBefore = ProfileHash();
try
{
    using var identity = WindowsIdentity.GetCurrent();
    Require(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), "Requires UAC elevation");
    Console.WriteLine($"START {DateTimeOffset.Now:O}; OS={Environment.OSVersion}; Whale={FileVersionInfo.GetVersionInfo(whaleExe).FileVersion}; soak={soakText}s");
    DivertEngine.CheckDriver();
    using var handles = new DriverHandles();
    using var sink = DriverHandles.TestSink();
    await using var server = new FixtureServer();
    var fixtureDirectory = Path.Combine(outputDirectory, "profile");
    new ProfileStore(fixtureDirectory).Save(new Profile
    {
        Proxies = [new ProxyServer { Id = "fixture", Name = "Local test peer", Host = "127.0.0.1", Port = server.Port, Kind = ProxyKind.Http }],
        Rules = [new RoutingRule { Name = "Whale fixture", Destinations = "203.0.113.10", Ports = "18080", ProcessName = "whale.exe", Action = RuleAction.Proxy, ProxyId = "fixture" }]
    });
    await using var whale = await WhaleClient.Start(whaleExe, Path.Combine(outputDirectory, "whale-profile-" + Guid.NewGuid().ToString("N")));
    lock (children) children.Add(whale.Process);
    var direct = $"http://127.0.0.1:{server.Port}";
    const string diverted = "http://203.0.113.10:18080";
    await whale.Command("Page.navigate", new { url = direct });
    await Task.Delay(500);
    var baseline = new List<double>();
    for (var i = 0; i < 3; i++) baseline.Add(await whale.Transfer(direct, 33554432));
    Console.WriteLine($"BENCH direct Whale 32MiB download ms={JsonSerializer.Serialize(baseline)}");
    var app = await StartApp();
    var root = AutomationElement.FromHandle(app.MainWindowHandle);
    await Invoke(root, "ObserveButton");
    await Wait.Until(() => handles.Count(app.Id, 2) == 1, "Monitor FLOW handle opened");
    var starts = new List<double>(); var stops = new List<double>();
    for (var i = 0; i < 20; i++)
    {
        var watch = Stopwatch.StartNew(); await Invoke(root, "ToggleButton");
        await Wait.Until(() => handles.Count(app.Id, 0) == 1 && Text(root, "StatusText").Contains("Active"), "Apply active");
        starts.Add(watch.Elapsed.TotalMilliseconds);
        await whale.Transfer(diverted);
        watch.Restart(); await Invoke(root, "ToggleButton");
        await Wait.Until(() => handles.Count(app.Id, 0) == 0 && Text(root, "StatusText").Contains("Stopped"), "Stop released NETWORK handle");
        stops.Add(watch.Elapsed.TotalMilliseconds);
        Require(handles.Count(app.Id, 2) == 1, "Stop must retain monitor until explicitly stopped");
    }
    Console.WriteLine($"PASS 20 apply/stop cycles; apply_ms={JsonSerializer.Serialize(starts)}; stop_ms={JsonSerializer.Serialize(stops)}");
    await Invoke(root, "ToggleButton");
    await Wait.Until(() => handles.Count(app.Id, 0) == 1, "Benchmark apply");
    var proxyTimes = new List<double>();
    for (var i = 0; i < 3; i++) proxyTimes.Add(await whale.Transfer(diverted, 33554432));
    Console.WriteLine($"BENCH intercepted Whale 32MiB download ms={JsonSerializer.Serialize(proxyTimes)}; CONNECTs={server.Connects}");
    var samples = new List<object>(); var soak = Stopwatch.StartNew(); var transfers = 0;
    while (soak.Elapsed.TotalSeconds < int.Parse(soakText))
    {
        await whale.Transfer(diverted, 4194304); transfers++;
        app.Refresh();
        if (transfers == 1 || transfers % 15 == 0)
        {
            var sample = new { seconds = Math.Round(soak.Elapsed.TotalSeconds, 2), app.WorkingSet64, app.PrivateMemorySize64, app.HandleCount, threads = app.Threads.Count, cpuSeconds = app.TotalProcessorTime.TotalSeconds, stats = Text(root, "StatsText"), transfers };
            samples.Add(sample); Console.WriteLine("SAMPLE " + JsonSerializer.Serialize(sample));
        }
        Require(handles.Error is null && handles.Count(app.Id, 0) == 1 && handles.Count(app.Id, 2) == 1, "Capture/monitor stays active");
        await Task.Delay(2000);
    }
    File.WriteAllText(Path.Combine(outputDirectory, "samples.json"), JsonSerializer.Serialize(samples, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"PASS soak {soak.Elapsed.TotalSeconds:F1}s; transfers={transfers}; stats={Text(root, "StatsText")}");
    await Invoke(root, "ToggleButton");
    await Wait.Until(() => handles.Count(app.Id, 0) == 0, "Post-soak stop");
    await Invoke(root, "ObserveButton");
    await Wait.Until(() => handles.Count(app.Id) == 0, "Stop monitor releases final handle");
    await whale.Transfer(direct);
    Console.WriteLine("PASS stop + stop monitor: zero GUI WinDivert handles; direct Whale transfer intact");
    // Keep fetches in flight while exercising the normal window-close and abrupt process-death paths.
    for (var mode = 0; mode < 2; mode++)
    {
        if (mode != 0) { app = await StartApp(); root = AutomationElement.FromHandle(app.MainWindowHandle); }
        await Invoke(root, "ObserveButton"); await Invoke(root, "ToggleButton");
        await Wait.Until(() => handles.Count(app.Id) == 2 && Text(root, "StatusText").Contains("Active"), "Exit-test capture active");
        await whale.Transfer(diverted);
        await whale.Evaluate("window.completed=0; window.pending=Array.from({length:8},()=>fetch('" + diverted + "/bytes/33554432?'+Math.random(),{signal:AbortSignal.timeout(5000)}).then(r=>r.arrayBuffer()).then(()=>true,()=>false).finally(()=>window.completed++)); 'started'");
        await Task.Delay(100);
        Require((await whale.Evaluate("window.completed")).GetInt32() < 8, "Transfers must still be in flight when closing");
        var watch = Stopwatch.StartNew();
        if (mode == 0) Require(app.CloseMainWindow(), "Send standard window close (X/WM_CLOSE)"); else app.Kill();
        await app.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        await Wait.Until(() => handles.Count(app.Id) == 0, "All GUI handles released after exit");
        var exitMilliseconds = watch.Elapsed.TotalMilliseconds;
        var connects = server.Connects;
        await whale.Evaluate("Promise.all(window.pending)");
        var stopped = await whale.Evaluate("fetch('" + diverted + "/bytes/16?'+Math.random(),{signal:AbortSignal.timeout(1500)}).then(()=>false,()=>true)");
        Require(stopped.GetBoolean() && server.Connects == connects, "No orphan relay after exit");
        await whale.Transfer(direct);
        Console.WriteLine($"PASS {(mode == 0 ? "X/WM_CLOSE" : "TerminateProcess")} during traffic; exit+release_ms={exitMilliseconds:F1}; GUI handles=0; no orphan relay; direct Whale intact");
    }
    Require(ProfileHash() == profileBefore, "User encrypted profile changed");
    Require(handles.Error is null, "REFLECT reader failed");
    Console.WriteLine($"PASS user profile unchanged; fixture requests={server.Requests}, bytes={server.Bytes}, CONNECTs={server.Connects}");
    Console.WriteLine($"COMPLETE {DateTimeOffset.Now:O}");
    return 0;

    async Task<Process> StartApp()
    {
        var info = new ProcessStartInfo(appExe) { UseShellExecute = false };
        info.ArgumentList.Add("--driver-fixture"); info.ArgumentList.Add(fixtureDirectory);
        var child = Process.Start(info)!; lock (children) children.Add(child);
        await Wait.Until(() => { child.Refresh(); return child.MainWindowHandle != IntPtr.Zero; }, "ProxyWin test window", 20);
        await Wait.Until(() => Find(AutomationElement.FromHandle(child.MainWindowHandle), "ToggleButton").Current.IsEnabled, "Window ready");
        return child;
    }
}
catch (Exception ex) { Console.WriteLine("FAIL " + ex); return 1; }
finally
{
    foreach (var child in children)
    {
        try { if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); } } catch (InvalidOperationException) { }
        child.Dispose();
    }
    Console.WriteLine("FINAL user profile unchanged=" + (ProfileHash() == profileBefore));
}

static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
static AutomationElement Find(AutomationElement root, string id) => root.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.AutomationIdProperty, id)) ?? throw new Exception("UI element missing: " + id);
static string Text(AutomationElement root, string id) => Find(root, id).Current.Name;
static async Task Invoke(AutomationElement root, string id)
{
    await Wait.Until(() => Find(root, id).Current.IsEnabled, id + " enabled");
    ((InvokePattern)Find(root, id).GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    await Task.Delay(50);
}
