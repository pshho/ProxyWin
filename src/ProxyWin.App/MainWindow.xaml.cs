using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using ProxyWin.Core;
using ProxyWin.Windows;

namespace ProxyWin.App;

public partial class MainWindow : Window
{
    private readonly ProfileStore store;
    private readonly DivertEngine engine = new();
    private readonly ConnectionObserver observer = new();
    private readonly bool smokeMode;
    private Profile profile = new();
    private bool busy, closing, closed, loadFailed;
    private readonly ConcurrentQueue<string> pendingLogs = new();
    private readonly ObservableCollection<string> logs = [];
    private readonly ObservableCollection<ObservedConnection> observations = [];
    private ICollectionView? observationView;
    private bool observerBusy;
    private string? observedError;
    private readonly DispatcherTimer timer;
    public MainWindow(ProfileStore store, bool smokeMode = false)
    {
        InitializeComponent(); this.store = store; this.smokeMode = smokeMode;
        ProcessPicker.Attach(ProcessBox);
        engine.Log += QueueLog;
        engine.Exited += () => Dispatcher.BeginInvoke(() => { if (!closing) Refresh(); });
        LogList.ItemsSource = logs;
        observationView = CollectionViewSource.GetDefaultView(observations);
        observationView.Filter = MatchesObservationFilter;
        ObservationGrid.ItemsSource = observationView;
        timer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => Tick(), Dispatcher);
        try { profile = store.Load(); } catch (Exception ex) { loadFailed = true; Loaded += (_, _) => Error(ex); }
        Refresh();
    }
    private void QueueLog(string message)
    {
        pendingLogs.Enqueue($"{DateTime.Now:HH:mm:ss}  {message}");
        while (pendingLogs.Count > 500) pendingLogs.TryDequeue(out _);
    }
    private void Tick()
    {
        for (var i = 0; i < 100 && pendingLogs.TryDequeue(out var line); i++) { logs.Add(line); if (logs.Count > 500) logs.RemoveAt(0); }
        for (var i = 0; i < 100 && observer.TryRead(out var connection); i++) AddObservation(connection!);
        if (observer.LastError is { } error && error != observedError) { observedError = error; QueueLog(error); }
        RefreshObservationControls();
        var s = engine.Statistics;
        StatsText.Text = $"TCP {s.TcpConnections} · UDP {s.UdpAssociations}   ↑ {s.Uploaded / 1048576d:F1} MB  ↓ {s.Downloaded / 1048576d:F1} MB   Blocked {s.Blocked} · Dropped {s.Dropped} · Errors {s.Errors}";
    }
    private sealed record RuleRow(RoutingRule Rule, string TargetName)
    {
        public bool Enabled => Rule.Enabled;
        public string Destinations => Rule.Destinations;
        public string Ports => Rule.Ports;
        public string NetworkLabel => Rule.NetworkLabel;
        public string ActionLabel => Rule.ActionLabel;
        public string ProcessLabel => Rule.ProcessName.Length == 0 ? "All" : Rule.ProcessName;
    }
    private bool CanEdit => !busy && !engine.IsRunning && !loadFailed;
    private RuleAction SelectedAction => (RuleAction)Math.Max(0, ActionBox.SelectedIndex);
    private void Refresh(string? selectedProxy = null)
    {
        var selected = selectedProxy ?? ProxyBox.SelectedValue as string;
        if (!profile.Proxies.Any(p => p.Id == selected)) selected = profile.Proxies.FirstOrDefault()?.Id;
        ProxyBox.ItemsSource = profile.Proxies; ProxyBox.SelectedValue = selected ?? profile.Proxies.FirstOrDefault()?.Id;
        RulesGrid.ItemsSource = profile.Rules.Select(r => new RuleRow(r, r.Action != RuleAction.Proxy ? "—" : profile.Proxies.FirstOrDefault(p => p.Id == r.ProxyId)?.Name ?? "Missing")).ToList();
        RuleCount.Text = $"Rules {profile.Rules.Count} · First match wins"; RuleEmpty.Visibility = profile.Rules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EditorPanel.IsEnabled = RulePanel.IsEnabled = CanEdit;
        ToggleButton.IsEnabled = !busy && !loadFailed && (engine.IsRunning || profile.Rules.Any(r => r.Enabled));
        ToggleButton.Content = busy ? "Working…" : engine.IsRunning ? "■ Stop" : "▶ Apply";
        StatusText.Text = busy ? "● Working" : engine.IsRunning ? "● Active" : "● Stopped";
        FooterText.Text = loadFailed ? "Profile unavailable · Editing locked" : engine.IsRunning ? "Active · Stop to edit rules" : "Auto-saved · PROXY affects new TCP connections";
        RefreshObservationControls();
    }
    private bool Change(Action<Profile> mutation, string? selected = null)
    {
        if (!CanEdit) return false;
        try
        {
            var next = JsonSerializer.Deserialize<Profile>(JsonSerializer.Serialize(profile))!; mutation(next);
            RuleParser.Validate(next); if (!smokeMode) store.Save(next);
            profile = next; Refresh(selected); return true;
        }
        catch (Exception ex) { Error(ex); return false; }
    }
    private void AddProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        var dialog = new ProxyDialog(null) { Owner = this };
        if (dialog.ShowDialog() == true) Change(p => p.Proxies.Add(dialog.Result!), dialog.Result!.Id);
    }
    private void EditProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || ProxyBox.SelectedItem is not ProxyServer proxy) return;
        var dialog = new ProxyDialog(proxy) { Owner = this };
        if (dialog.ShowDialog() == true) Change(p => p.Proxies[p.Proxies.FindIndex(x => x.Id == proxy.Id)] = dialog.Result!, proxy.Id);
    }
    private void DeleteProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || ProxyBox.SelectedItem is not ProxyServer proxy) return;
        if (profile.Rules.Any(r => r.Action == RuleAction.Proxy && r.ProxyId == proxy.Id)) { Error(new InvalidOperationException("Remove or update rules using this proxy first.")); return; }
        if (AppMessages.Confirm(this, $"Remove proxy '{proxy.Name}'?", "Remove proxy")) Change(p => p.Proxies.RemoveAll(x => x.Id == proxy.Id));
    }
    private void AddTarget(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        var proxy = ProxyBox.SelectedItem as ProxyServer;
        if (SelectedAction == RuleAction.Proxy && proxy is null) { Error(new InvalidOperationException("Select a proxy server first.")); return; }
        try
        {
            var rule = new RoutingRule { Name = TargetBox.Text.Trim(), Destinations = TargetBox.Text.Trim(), Ports = PortBox.Text.Trim(), Network = (Transport)ProtocolBox.SelectedIndex, Action = SelectedAction,
                ProxyId = SelectedAction == RuleAction.Proxy ? proxy!.Id : SelectedAction == RuleAction.Direct ? "direct" : "block", ProcessName = ProcessBox.Text.Trim() };
            _ = new CapturePlan(new Profile { Proxies = profile.Proxies, Rules = [rule] });
            if (Change(p => p.Rules.Add(rule))) { TargetBox.Clear(); TargetBox.Focus(); }
        }
        catch (Exception ex) { Error(ex); }
    }
    private void EditRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = profile.Rules.IndexOf(row.Rule); var dialog = new RuleDialog(row.Rule, profile.Proxies) { Owner = this };
        if (dialog.ShowDialog() == true) Change(p => p.Rules[index] = dialog.Result!);
    }
    private void DeleteRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = profile.Rules.IndexOf(row.Rule); Change(p => p.Rules.RemoveAt(index));
    }
    private void ToggleRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || sender is not CheckBox { DataContext: RuleRow row } check) return;
        var index = profile.Rules.IndexOf(row.Rule); Change(p => p.Rules[index].Enabled = check.IsChecked == true);
    }
    private void MoveRuleUp(object sender, RoutedEventArgs e) => MoveRule(-1);
    private void MoveRuleDown(object sender, RoutedEventArgs e) => MoveRule(1);
    private void MoveRule(int delta)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = profile.Rules.IndexOf(row.Rule); var target = index + delta;
        if (target < 0 || target >= profile.Rules.Count) return;
        Change(p => { var item = p.Rules[index]; p.Rules.RemoveAt(index); p.Rules.Insert(target, item); }); RulesGrid.SelectedIndex = target;
    }
    private async void ToggleEngine(object sender, RoutedEventArgs e)
    {
        if (busy || smokeMode || loadFailed) return;
        busy = true; Refresh();
        try
        {
            if (engine.IsRunning) await engine.StopAsync();
            else
            {
                _ = new CapturePlan(profile);
                using var identity = WindowsIdentity.GetCurrent();
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException("Run ProxyWin as administrator.");
                store.Save(profile); await engine.StartAsync(profile);
            }
        }
        catch (Exception ex) { Error(ex); }
        finally { busy = false; Refresh(); }
    }
    private void ClearLogs(object sender, RoutedEventArgs e) { pendingLogs.Clear(); logs.Clear(); }
    private void OpenProcessPicker(object sender, EventArgs e)
    {
        try { ProcessPicker.Refresh((ComboBox)sender); } catch (Exception ex) { Error(ex); }
    }
    private async void ToggleObservation(object sender, RoutedEventArgs e)
    {
        if (observerBusy || smokeMode || closing) return;
        observerBusy = true; RefreshObservationControls();
        try
        {
            if (observer.IsRunning) { await observer.StopAsync(); QueueLog("Monitor stopped. Rules are unchanged."); }
            else { await observer.StartAsync(); observedError = null; QueueLog("Monitor started. New TCP/UDP connections only; stored in memory."); }
        }
        catch (Exception ex) { Error(ex); }
        finally { observerBusy = false; RefreshObservationControls(); }
    }
    private void AddObservation(ObservedConnection connection)
    {
        observations.Insert(0, connection);
        if (observations.Count > 1000) observations.RemoveAt(observations.Count - 1);
    }
    private bool MatchesObservationFilter(object item)
    {
        if (item is not ObservedConnection connection) return false;
        var term = ObservationFilter.Text.Trim();
        return term.Length == 0 || connection.ProcessLabel.Contains(term, StringComparison.OrdinalIgnoreCase)
            || connection.ProcessId.ToString().Contains(term) || connection.Destination.Contains(term, StringComparison.OrdinalIgnoreCase)
            || connection.RemotePort.ToString().Contains(term) || connection.LocalEndpoint.Contains(term, StringComparison.OrdinalIgnoreCase)
            || connection.NetworkLabel.Contains(term, StringComparison.OrdinalIgnoreCase);
    }
    private void FilterObservations(object sender, TextChangedEventArgs e)
    {
        observationView?.Refresh();
        if (!IsInitialized) return;
        if (ObservationGrid.SelectedItem is ObservedConnection row && !MatchesObservationFilter(row)) ObservationGrid.SelectedItem = null;
        RefreshObservationControls();
    }
    private void SelectionChanged(object sender, SelectionChangedEventArgs e) { if (IsInitialized) RefreshObservationControls(); }
    private void ObservationScopeChanged(object sender, RoutedEventArgs e) { if (IsInitialized) RefreshObservationControls(); }
    private void ActionChanged(object sender, SelectionChangedEventArgs e) { if (IsInitialized) RefreshObservationControls(); }
    private void RefreshObservationControls()
    {
        if (!IsInitialized) return;
        ObserveButton.IsEnabled = !observerBusy && !closing;
        ObserveButton.Content = observerBusy ? "Working…" : observer.IsRunning ? "Stop monitor" : "Start monitor";
        ObserveStatus.Text = $"{(smokeMode ? "Preview data" : observer.IsRunning ? "Monitoring" : observer.LastError is null ? "Stopped" : "Stopped: error")} · {observations.Count} / 1000 rows" + (observer.Skipped > 0 ? $" · Skipped {observer.Skipped}" : "");
        var row = ObservationGrid.SelectedItem as ObservedConnection;
        var proxy = ProxyBox.SelectedItem as ProxyServer;
        string? reason = !CanEdit ? "Stop rules to edit. Monitoring can stay on."
            : SelectedAction == RuleAction.Proxy && proxy is null ? "Select a proxy server first."
            : row is null ? "Select a connection."
            : !row.CanRoute ? "Local, multicast and IPv6 link-local connections cannot be routed."
            : OnlyObservedProgram.IsChecked == true && row.ProcessName is null ? "Process name unavailable. Capture a new connection or clear 'This process'."
            : SelectedAction == RuleAction.Proxy && proxy?.Kind == ProxyKind.Http && row.Network == Transport.Udp ? "UDP requires a SOCKS5 server." : null;
        AddObservedButton.IsEnabled = reason is null;
        AddObservedButton.ToolTip = reason ?? $"Add a {SelectedAction.ToString().ToUpperInvariant()} rule for this connection.";
        ToolTipService.SetShowOnDisabled(AddObservedButton, true);
    }
    private void AddObservedRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || ObservationGrid.SelectedItem is not ObservedConnection row) return;
        try
        {
            var proxy = ProxyBox.SelectedItem as ProxyServer;
            var rule = row.CreateRule(proxy?.Id ?? "", OnlyObservedProgram.IsChecked == true, SelectedAction);
            _ = new CapturePlan(new Profile { Proxies = profile.Proxies, Rules = [rule] });
            var index = profile.Rules.FindIndex(r => SameRule(r, rule));
            if (index >= 0)
            {
                if (!profile.Rules[index].Enabled) Change(p => p.Rules[index].Enabled = true);
                QueueLog("Existing rule selected.");
            }
            else
            {
                if (!Change(p => p.Rules.Add(rule))) return;
                index = profile.Rules.Count - 1;
                QueueLog($"Added {rule.ActionLabel}: {rule.ProcessName switch { "" => "All processes", var name => name }} → {rule.Destinations}:{rule.Ports} ({rule.NetworkLabel})");
            }
            RulesGrid.SelectedIndex = index;
            RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
        }
        catch (Exception ex) { Error(ex); }
    }
    private static bool SameRule(RoutingRule a, RoutingRule b)
    {
        static string Program(string name) => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        return a.Action == b.Action && (a.Action != RuleAction.Proxy || a.ProxyId == b.ProxyId) && a.Network == b.Network && string.Equals(Program(a.ProcessName), Program(b.ProcessName), StringComparison.OrdinalIgnoreCase)
            && RuleParser.Networks(a.Destinations).Order().SequenceEqual(RuleParser.Networks(b.Destinations).Order())
            && RuleParser.Ports(a.Ports).OrderBy(p => p.Start).ThenBy(p => p.End).SequenceEqual(RuleParser.Ports(b.Ports).OrderBy(p => p.Start).ThenBy(p => p.End));
    }
    private void ClearObservations(object sender, RoutedEventArgs e) { observer.Clear(); observations.Clear(); RefreshObservationControls(); }
    private void Error(Exception ex) => AppMessages.Error(this, ex);
    internal void VerifySmokeBindings()
    {
        if (!smokeMode) throw new InvalidOperationException();
        Change(p => { p.Proxies.Add(new ProxyServer { Id = "sample", Name = "Local SOCKS5", Host = "127.0.0.1" }); p.Proxies.Add(new ProxyServer { Id = "burp", Name = "Burp · 127.0.0.1:8080", Host = "127.0.0.1", Port = 8080, Kind = ProxyKind.Http }); }, "burp");
        TargetBox.Text = "203.0.113.10"; PortBox.Text = "443"; ProcessBox.Text = "chrome.exe"; AddTarget(this, new RoutedEventArgs());
        ProxyBox.SelectedValue = "sample"; TargetBox.Text = "2001:db8::/32"; PortBox.Text = "5000-5100"; ProcessBox.Text = ""; ProtocolBox.SelectedIndex = 1; AddTarget(this, new RoutedEventArgs());
        if (RulesGrid.Items.Count != 2 || !ToggleButton.IsEnabled) throw new InvalidOperationException("GUI bindings failed.");
        RulesGrid.SelectedIndex = 1; MoveRule(-1); if (profile.Rules[0].Network != Transport.Udp) throw new InvalidOperationException("Reordering failed.");
        var row = (RuleRow)RulesGrid.Items[0]; ToggleRule(new CheckBox { DataContext = row, IsChecked = false }, new RoutedEventArgs());
        if (profile.Rules[0].Enabled) throw new InvalidOperationException("Rule toggle failed.");
        ProtocolBox.SelectedIndex = 0; PortBox.Text = "*";
        var observed = new ObservedConnection(DateTimeOffset.Now, 4321, "curl.exe", IPAddress.Parse("192.0.2.2"), 52000, IPAddress.Parse("203.0.113.20"), 8443, Transport.Tcp, false);
        AddObservation(observed);
        AddObservation(observed with { ProcessId = 1234, ProcessName = "chrome.exe", RemoteAddress = IPAddress.Parse("203.0.113.10"), RemotePort = 443 });
        AddObservation(observed with { ProcessId = 3210, ProcessName = "game.exe", RemoteAddress = IPAddress.Parse("2001:db8::20"), RemotePort = 5000, Network = Transport.Udp });
        ObservationGrid.SelectedItem = observed;
        AddObservedRule(this, new RoutedEventArgs()); AddObservedRule(this, new RoutedEventArgs());
        if (profile.Rules.Count != 3 || profile.Rules[^1].ProcessName != "curl.exe" || profile.Rules[^1].Ports != "8443") throw new InvalidOperationException("Observed rule creation / duplicate protection failed.");
        ObservationFilter.Text = "curl.exe";
        if (observationView!.Cast<ObservedConnection>().Count() != 1) throw new InvalidOperationException("Observation filter failed.");
        ObservationFilter.Text = "chrome.exe";
        if (ObservationGrid.SelectedItem is not null) throw new InvalidOperationException("Hidden observation selection was retained.");
        ObservationFilter.Clear(); ObservationGrid.SelectedItem = observed; RefreshObservationControls();
        ProcessBox.Text = ""; ProcessPicker.Refresh(ProcessBox);
        if (ProcessBox.Items.Count == 0) throw new InvalidOperationException("Process picker has no running processes.");
        var firstName = (string)ProcessBox.Items[0]; var query = firstName[..Math.Min(3, firstName.Length)];
        ProcessPicker.Search(ProcessBox, query);
        if (ProcessBox.Items.Count == 0 || ProcessBox.Items.Cast<string>().Any(n => !n.Contains(query, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Process search did not filter.");
        if (!ProcessPicker.Filter(["chrome.exe", "msedge.exe", "notepad.exe"], "ROME").SequenceEqual(["chrome.exe"])) throw new InvalidOperationException("Substring / case-insensitive search failed.");
        ProcessBox.Text = "manual.exe"; ProcessPicker.Refresh(ProcessBox);
        if (ProcessBox.Text != "manual.exe") throw new InvalidOperationException("Process search overwrote typed input.");
        ProcessBox.Text = "";
        ActionBox.SelectedIndex = (int)RuleAction.Direct; TargetBox.Text = "198.51.100.10"; PortBox.Text = "443"; AddTarget(this, new RoutedEventArgs());
        ActionBox.SelectedIndex = (int)RuleAction.Block; TargetBox.Text = "198.51.100.20"; ProtocolBox.SelectedIndex = 2; AddTarget(this, new RoutedEventArgs());
        if (profile.Rules[^2].Action != RuleAction.Direct || profile.Rules[^1].Action != RuleAction.Block) throw new InvalidOperationException("DIRECT/BLOCK quick-add failed.");
        if (Icon is null) throw new InvalidOperationException("Application icon not loaded.");
        RulesGrid.SelectedIndex = profile.Rules.Count - 1; RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
        ProtocolBox.SelectedIndex = 0; ActionBox.SelectedIndex = (int)RuleAction.Proxy;
        TargetBox.Text = "*"; PortBox.Text = "*"; ProcessBox.Text = "worker.exe"; ProtocolBox.SelectedIndex = 2;
        AddTarget(this, new RoutedEventArgs());
        if (profile.Rules[^1].Destinations != "*" || profile.Rules[^1].ProcessName != "worker.exe") throw new InvalidOperationException("Process-only wildcard rule failed.");
        ProcessBox.Text = ""; ProtocolBox.SelectedIndex = 0;
        RulesGrid.SelectedIndex = profile.Rules.Count - 1; RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
    }
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (closed) return; e.Cancel = true; if (closing) return;
        closing = true; IsEnabled = false;
        try { try { await observer.DisposeAsync(); } finally { await engine.DisposeAsync(); } } catch (Exception ex) { Error(ex); }
        finally { timer.Stop(); closed = true; Close(); }
    }

    internal async Task VerifyProcessCaretAsync()
    {
        if (!smokeMode) throw new InvalidOperationException();
        Activate(); ProcessBox.ApplyTemplate();
        var editor = (TextBox)ProcessBox.Template.FindName("PART_EditableTextBox", ProcessBox);
        editor.Focus();
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (!editor.IsKeyboardFocused) throw new InvalidOperationException("Test fixture could not focus the process editor.");
        ProcessBox.Text = ""; editor.Select(0, 0);
        async Task Type(string text, string expected, int caret)
        {
            var composition = new System.Windows.Input.TextComposition(System.Windows.Input.InputManager.Current, editor, text);
            System.Windows.Input.TextCompositionManager.StartComposition(composition);
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            if (editor.Text != expected || editor.CaretIndex != caret || editor.SelectionLength != 0)
                throw new InvalidOperationException($"Typing {text}: text='{editor.Text}', caret={editor.CaretIndex}, selection={editor.SelectionLength}; expected {expected} / {caret} / 0.");
        }
        await Type("w", "w", 1);
        await Type("i", "wi", 2);
        editor.Select(1, 0); await Type("n", "wni", 2);
        editor.Select(1, 1); await Type("m", "wmi", 2);
        editor.SelectAll(); await Type("window.exe", "window.exe", 10);
        System.Windows.Documents.EditingCommands.Backspace.Execute(null, editor);
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (editor.Text != "window.ex" || editor.CaretIndex != 9) throw new InvalidOperationException("Backspace moved the caret.");
        editor.SelectAll(); editor.SelectedText = "";
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (editor.Text != "" || editor.CaretIndex != 0) throw new InvalidOperationException("Clearing the query failed.");
        await Type("not-running-manual.exe", "not-running-manual.exe", "not-running-manual.exe".Length);
        ProcessBox.IsDropDownOpen = false;
    }
}
