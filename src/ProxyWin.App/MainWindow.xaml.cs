using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
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
    private readonly Func<string, CancellationToken, Task<string>> resolveDestinations;
    private Profile profile = new();
    private bool busy, closing, closed, loadFailed;
    private bool resolving, saving;
    private Task? pendingSave;
    private readonly CancellationTokenSource lifetime = new();
    private Task? cleanupGuard;
    private readonly ConcurrentQueue<string> pendingLogs = new();
    private readonly ObservableCollection<string> logs = [];
    private readonly ObservableCollection<ObservedConnection> observations = [];
    private ICollectionView? observationView;
    private bool observerBusy;
    private string? observedError;
    private readonly DispatcherTimer timer;
    private const string ExistingRuleMessage = "같은 규칙이 이미 있어 기존 규칙을 선택했습니다.";
    private const string NeedsAdministrator = "관리자 권한이 필요합니다. 위쪽 노란 안내의 [관리자 권한으로 다시 실행]을 누르거나, ProxyWin.exe를 우클릭 → '관리자 권한으로 실행' 하세요.";
    private const string NeedsProxy = "PROXY 규칙에는 프록시 서버가 필요합니다. 먼저 ①에서 [+ 서버 추가]로 서버를 등록하세요.\n(프록시 없이 그대로 보내거나 막으려면 동작을 DIRECT/BLOCK으로 바꾸세요.)";
    public MainWindow(ProfileStore store, bool smokeMode = false) : this(store, smokeMode, DestinationResolver.ResolveAsync) { }
    internal MainWindow(ProfileStore store, bool smokeMode, Func<string, CancellationToken, Task<string>> resolveDestinations)
    {
        InitializeComponent(); this.store = store; this.smokeMode = smokeMode;
        this.resolveDestinations = resolveDestinations;
        ProcessPicker.Attach(ProcessBox);
        engine.Log += QueueLog;
        engine.Exited += () => Dispatcher.BeginInvoke(async () => { if (!closing) { await UnloadDriverAsync(); Refresh(); } });
        LogList.ItemsSource = logs;
        observationView = CollectionViewSource.GetDefaultView(observations);
        observationView.Filter = MatchesObservationFilter;
        ObservationGrid.ItemsSource = observationView;
        timer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => Tick(), Dispatcher);
        // 규칙 적용·모니터는 관리자 권한이 필요하므로 미리 알려 준다(스모크 테스트 화면은 고정).
        if (!smokeMode && !IsAdministrator()) AdminBanner.Visibility = Visibility.Visible;
        try { profile = store.Load(); } catch (Exception ex) { loadFailed = true; Loaded += (_, _) => Error(ex); }
        Refresh();
    }
    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
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
        StatsText.Text = $"TCP {s.TcpConnections} · UDP {s.UdpAssociations}   ↑ {s.Uploaded / 1048576d:F1} MB  ↓ {s.Downloaded / 1048576d:F1} MB   차단 {s.Blocked} · 폐기 {s.Dropped} · 오류 {s.Errors}";
        // 오류가 생기면 접힌 로그 제목에서 바로 알 수 있게 한다.
        var header = s.Errors > 0 ? $"이벤트 로그 · 오류 {s.Errors}건 (펼쳐서 원인 확인)" : logs.Count > 0 ? $"이벤트 로그 · {logs.Count}건" : "이벤트 로그";
        if (!Equals(EventsPanel.Header, header)) EventsPanel.Header = header;
    }
    private sealed record RuleRow(RoutingRule Rule, string TargetName)
    {
        public bool Enabled => Rule.Enabled;
        public string Destinations => Rule.Destinations;
        public string Ports => Rule.Ports;
        public string NetworkLabel => Rule.NetworkLabel;
        public string ActionLabel => Rule.ActionLabel;
        public string ProcessLabel => Rule.ProcessName.Length == 0 ? "전체" : Rule.ProcessName;
    }
    private bool CanEdit => !busy && !resolving && !saving && !closing && !engine.IsRunning && !loadFailed;
    private RuleAction SelectedAction => (RuleAction)Math.Max(0, ActionBox.SelectedIndex);
    private void Refresh(string? selectedProxy = null)
    {
        var selected = selectedProxy ?? ProxyBox.SelectedValue as string;
        if (!profile.Proxies.Any(p => p.Id == selected)) selected = profile.Proxies.FirstOrDefault()?.Id;
        ProxyBox.ItemsSource = profile.Proxies; ProxyBox.SelectedValue = selected ?? profile.Proxies.FirstOrDefault()?.Id;
        RulesGrid.ItemsSource = profile.Rules.Select(r => new RuleRow(r, r.Action != RuleAction.Proxy ? "—" : profile.Proxies.FirstOrDefault(p => p.Id == r.ProxyId)?.Name ?? "없음(삭제됨)")).ToList();
        RuleCount.Text = $"규칙 목록 ({profile.Rules.Count}개)";
        // 규칙이 없으면 빈 표 대신 시작 가이드만 보여 준다.
        RuleEmpty.Visibility = profile.Rules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        RulesGrid.Visibility = profile.Rules.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        // 서버가 없으면 첫 단계인 [+ 서버 추가]를 강조한다.
        AddProxyButton.Style = (Style)AddProxyButton.FindResource(profile.Proxies.Count == 0 ? "Primary" : typeof(Button));
        EditProxyButton.IsEnabled = DeleteProxyButton.IsEnabled = profile.Proxies.Count > 0;
        GuideServerTitle.Text = profile.Proxies.Count > 0 ? "✔ ① 프록시 서버 (등록됨)" : "① 프록시 서버";
        EditorPanel.IsEnabled = RulePanel.IsEnabled = CanEdit;
        var hasEnabledRule = profile.Rules.Any(r => r.Enabled);
        ToggleButton.IsEnabled = !busy && !resolving && !closing && !loadFailed && (engine.IsRunning || hasEnabledRule);
        ToggleButton.Content = busy ? "처리 중…" : engine.IsRunning ? "■ 적용 중지" : "▶ 규칙 적용";
        ToggleButton.ToolTip = engine.IsRunning ? "규칙 적용을 멈추고 모든 트래픽을 원래대로 돌립니다."
            : hasEnabledRule ? "체크된 규칙을 적용합니다(관리자 권한 필요). 적용 후 대상 프로그램에서 새로 접속해야 프록시를 거칩니다."
            : "먼저 ② 규칙을 추가(또는 체크)하세요.";
        StatusText.Text = busy ? "● 처리 중" : engine.IsRunning ? "● 적용 중" : "● 중지됨";
        FooterText.Text = resolving ? "도메인 IP 확인 중…" : loadFailed ? "설정 파일을 읽을 수 없어 편집이 잠겼습니다"
            : engine.IsRunning ? "적용 중 · 대상 프로그램에서 새로 접속하면 프록시를 거칩니다 · 규칙을 바꾸려면 [■ 적용 중지]"
            : "설정은 자동 저장됩니다 · PROXY는 적용 후 새로 맺는 연결부터 적용";
        RefreshRuleHint();
        RefreshObservationControls();
    }
    private void RefreshRuleHint()
    {
        if (!IsInitialized) return;
        var proxy = ProxyBox.SelectedItem as ProxyServer;
        RuleHint.Text = SelectedAction switch
        {
            RuleAction.Proxy when proxy is null => "⚠ PROXY 규칙에는 프록시 서버가 필요합니다. 먼저 ①에서 [+ 서버 추가]를 누르세요.",
            RuleAction.Proxy => $"PROXY: 조건에 맞는 새 연결을 ①의 '{proxy!.Name}' 서버({proxy.Endpoint})로 보냅니다."
                + (proxy.Kind == ProxyKind.Http ? " HTTP 프록시는 TCP만 지원합니다." : " SOCKS5는 TCP·UDP 모두 가능합니다."),
            RuleAction.Direct => "DIRECT: 프록시 없이 그대로 보냅니다. 넓은 PROXY/BLOCK 규칙의 예외로 쓰려면 목록 위쪽에 두세요.",
            _ => "BLOCK: 조건에 맞는 연결을 차단합니다. 프로그램에는 시간 초과처럼 보입니다."
        };
        RuleHint.Foreground = (Brush)FindResource(SelectedAction == RuleAction.Proxy && proxy is null ? "WarnInk" : "Muted");
    }
    // 설정 저장(DPAPI 암호화·디스크 flush)은 UI 스레드를 멈추지 않도록 백그라운드에서 한다.
    // 저장이 끝날 때까지 다음 편집은 받지 않아 저장 순서가 섞이지 않고(화면은 그대로 둠),
    // 실패하면 메모리의 설정도 바꾸지 않아 이전 상태가 유지된다.
    private async Task<bool> ChangeAsync(Action<Profile> mutation, string? selected = null)
    {
        if (!CanEdit) return false;
        saving = true;
        Profile next;
        try
        {
            next = JsonSerializer.Deserialize<Profile>(JsonSerializer.Serialize(profile))!; mutation(next);
            RuleParser.Validate(next);
            if (!smokeMode)
            {
                var target = store; var snapshot = next;
                pendingSave = Task.Run(() => target.Save(snapshot));
                await pendingSave;
            }
        }
        catch (Exception ex) { saving = false; if (!closing) Error(ex); return false; }
        saving = false;
        profile = next; if (!closing) Refresh(selected);
        return true;
    }
    // RoutingRule은 record라 IndexOf는 값 비교를 한다. 내용이 같은 중복 규칙에서
    // 엉뚱한 행이 바뀌지 않도록 선택한 행의 객체 자체로 위치를 찾는다.
    private int IndexOf(RuleRow row) => profile.Rules.FindIndex(r => ReferenceEquals(r, row.Rule));
    private void SelectRule(int index)
    {
        if (index < 0 || index >= RulesGrid.Items.Count) return;
        RulesGrid.SelectedIndex = index;
        RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
    }
    private static string Describe(RoutingRule rule) =>
        $"{rule.ActionLabel} · {(rule.ProcessName.Length == 0 ? "모든 프로그램" : rule.ProcessName)} → {rule.Destinations} : {rule.Ports} ({rule.NetworkLabel})";
    private async void AddProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        var dialog = new ProxyDialog(null) { Owner = this };
        if (dialog.ShowDialog() == true && await ChangeAsync(p => p.Proxies.Add(dialog.Result!), dialog.Result!.Id))
        {
            QueueLog($"프록시 서버 추가: {dialog.Result.Summary}");
            // 서버를 처음 등록했다면 다음 단계(규칙 대상 입력)로 바로 안내한다.
            if (profile.Rules.Count == 0) { ActionBox.SelectedIndex = (int)RuleAction.Proxy; TargetBox.Focus(); }
        }
    }
    private async void EditProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || ProxyBox.SelectedItem is not ProxyServer proxy) return;
        var dialog = new ProxyDialog(proxy) { Owner = this };
        if (dialog.ShowDialog() == true) await ChangeAsync(p => p.Proxies[p.Proxies.FindIndex(x => x.Id == proxy.Id)] = dialog.Result!, proxy.Id);
    }
    private async void DeleteProxy(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || ProxyBox.SelectedItem is not ProxyServer proxy) return;
        var used = profile.Rules.Count(r => r.Action == RuleAction.Proxy && r.ProxyId == proxy.Id);
        if (used > 0) { Error(new InvalidOperationException($"'{proxy.Name}' 서버를 쓰는 규칙이 {used}개 있습니다. 해당 규칙을 먼저 삭제하거나 [수정]에서 다른 서버로 바꾸세요.")); return; }
        if (AppMessages.Confirm(this, $"프록시 서버 '{proxy.Name}'을(를) 삭제할까요?", "서버 삭제")) await ChangeAsync(p => p.Proxies.RemoveAll(x => x.Id == proxy.Id));
    }
    private async void AddTarget(object sender, RoutedEventArgs e) => await AddTargetAsync();
    private async Task AddTargetAsync()
    {
        if (!CanEdit) return;
        var proxy = ProxyBox.SelectedItem as ProxyServer;
        if (SelectedAction == RuleAction.Proxy && proxy is null) { Error(new InvalidOperationException(NeedsProxy)); return; }
        if (TargetBox.Text.Trim().Length == 0)
        {
            Error(new FormatException("대상을 입력하세요. 예: 203.0.113.10, api.example.com\n특정 프로그램의 모든 트래픽이면 대상과 포트에 * 를 넣고 프로그램을 고르세요."));
            TargetBox.Focus(); return;
        }
        try
        {
            var rule = new RoutingRule { Name = TargetBox.Text.Trim(), Destinations = TargetBox.Text.Trim(), Ports = PortBox.Text.Trim(), Network = (Transport)ProtocolBox.SelectedIndex, Action = SelectedAction,
                ProxyId = SelectedAction == RuleAction.Proxy ? proxy!.Id : SelectedAction == RuleAction.Direct ? "direct" : "block", ProcessName = ProcessBox.Text.Trim() };
            resolving = true; Refresh();
            try { rule.Destinations = await resolveDestinations(rule.Destinations, lifetime.Token); }
            finally { resolving = false; if (!closing) Refresh(); }
            if (closing) return;
            _ = new CapturePlan(new Profile { Proxies = profile.Proxies, Rules = [rule] });
            var existing = profile.Rules.FindIndex(r => SameRule(r, rule));
            if (existing >= 0)
            {
                // 같은 규칙을 또 만들지 않고 기존 규칙을 보여 준다(꺼져 있으면 다시 켬).
                if (!profile.Rules[existing].Enabled && !await ChangeAsync(p => p.Rules[existing].Enabled = true)) return;
                QueueLog(ExistingRuleMessage); SelectRule(existing); return;
            }
            if (await ChangeAsync(p => p.Rules.Add(rule)))
            {
                QueueLog("규칙 추가: " + Describe(rule));
                SelectRule(profile.Rules.Count - 1);
                TargetBox.Clear(); TargetBox.Focus();
            }
        }
        catch (OperationCanceledException) when (closing) { }
        catch (Exception ex) { if (!closing) Error(ex); }
    }
    private void FillProgramExample(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        TargetBox.Text = "*"; PortBox.Text = "*"; ProtocolBox.SelectedIndex = (int)Transport.Tcp;
        ActionBox.SelectedIndex = (int)RuleAction.Proxy; ProcessBox.Text = "";
        // 남은 입력은 프로그램 이름뿐이므로 실행 중인 프로그램 목록을 바로 연다.
        ProcessBox.Focus(); ProcessBox.IsDropDownOpen = true;
    }
    private void FillSiteExample(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        TargetBox.Text = "api.example.com"; PortBox.Text = "443"; ProtocolBox.SelectedIndex = (int)Transport.Tcp;
        ActionBox.SelectedIndex = (int)RuleAction.Proxy; ProcessBox.Text = "";
        TargetBox.Focus(); TargetBox.SelectAll();
    }
    private async void EditRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = IndexOf(row); if (index < 0) return;
        var dialog = new RuleDialog(row.Rule, profile.Proxies) { Owner = this };
        if (dialog.ShowDialog() == true && await ChangeAsync(p => p.Rules[index] = dialog.Result!)) SelectRule(index);
    }
    private async void DeleteRule(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = IndexOf(row); if (index < 0) return;
        await ChangeAsync(p => p.Rules.RemoveAt(index));
    }
    private async void ToggleRule(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox check) await ToggleRuleAsync(check);
    }
    internal async Task ToggleRuleAsync(CheckBox check)
    {
        if (check.DataContext is not RuleRow row) return;
        var index = CanEdit ? IndexOf(row) : -1;
        // 편집할 수 없거나 저장에 실패하면 체크 상태를 실제 설정값으로 되돌린다.
        if (index < 0 || !await ChangeAsync(p => p.Rules[index].Enabled = check.IsChecked == true))
            check.SetCurrentValue(CheckBox.IsCheckedProperty, row.Rule.Enabled);
    }
    private void MoveRuleUp(object sender, RoutedEventArgs e) => MoveRule(-1);
    private void MoveRuleDown(object sender, RoutedEventArgs e) => MoveRule(1);
    private async void MoveRule(int delta)
    {
        if (!CanEdit || RulesGrid.SelectedItem is not RuleRow row) return;
        var index = IndexOf(row); var target = index + delta;
        if (index < 0 || target < 0 || target >= profile.Rules.Count) return;
        if (await ChangeAsync(p => { var item = p.Rules[index]; p.Rules.RemoveAt(index); p.Rules.Insert(target, item); })) SelectRule(target);
    }
    private async void ToggleEngine(object sender, RoutedEventArgs e)
    {
        if (busy || resolving || saving || closing || smokeMode || loadFailed) return;
        busy = true; Refresh();
        try
        {
            if (engine.IsRunning) await engine.StopAsync();
            else
            {
                _ = new CapturePlan(profile);
                if (!IsAdministrator()) throw new InvalidOperationException(NeedsAdministrator);
                var target = store; var snapshot = profile;
                await Task.Run(() => target.Save(snapshot)); await EnsureCleanupGuardAsync();
                if (closing) return;
                await engine.StartAsync(profile);
            }
        }
        catch (Exception ex) { if (!closing) Error(ex); }
        finally { if (!engine.IsRunning) await UnloadDriverAsync(); busy = false; if (!closing) Refresh(); }
    }
    private void RestartAsAdmin(object sender, RoutedEventArgs e)
    {
        if (busy || closing || smokeMode) return;
        try { if (Application.Current is App app && app.RestartElevated()) Close(); }
        catch (Exception ex) { Error(ex); }
    }
    private Task EnsureCleanupGuardAsync()
    {
        if (cleanupGuard?.IsFaulted == true) cleanupGuard = null;
        return cleanupGuard ??= DriverCleanupGuard.StartAsync(store.DirectoryPath);
    }
    private async Task UnloadDriverAsync()
    {
        if (smokeMode || cleanupGuard is null) return;
        if (engine.IsRunning || observer.IsRunning) { QueueLog("규칙 적용 또는 연결 모니터가 실행 중이라 WinDivert 드라이버를 유지합니다."); return; }
        QueueLog((await DriverService.TryUnloadAsync()).Message);
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
            if (observer.IsRunning) { await observer.StopAsync(); QueueLog("연결 모니터를 중지했습니다. 규칙은 그대로입니다."); }
            else
            {
                if (!IsAdministrator()) throw new InvalidOperationException(NeedsAdministrator);
                await EnsureCleanupGuardAsync(); if (closing) return;
                await observer.StartAsync(); observedError = null; QueueLog("연결 모니터를 시작했습니다. 새 TCP/UDP 연결만 메모리에 표시합니다.");
            }
        }
        catch (Exception ex) { if (!closing) Error(ex); }
        finally { if (!observer.IsRunning) await UnloadDriverAsync(); observerBusy = false; if (!closing) RefreshObservationControls(); }
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
    private void SelectionChanged(object sender, SelectionChangedEventArgs e) { if (IsInitialized) { RefreshRuleHint(); RefreshObservationControls(); } }
    private void ObservationScopeChanged(object sender, RoutedEventArgs e) { if (IsInitialized) RefreshObservationControls(); }
    private void ActionChanged(object sender, SelectionChangedEventArgs e) { if (IsInitialized) { RefreshRuleHint(); RefreshObservationControls(); } }
    private void RefreshObservationControls()
    {
        if (!IsInitialized) return;
        ObserveButton.IsEnabled = !observerBusy && !closing;
        ObserveButton.Content = observerBusy ? "처리 중…" : observer.IsRunning ? "■ 모니터 중지" : "▶ 모니터 시작";
        ObserveStatus.Text = $"{(smokeMode ? "미리보기 데이터" : observer.IsRunning ? "모니터링 중" : observer.LastError is null ? "중지됨" : "오류로 중지됨")} · {observations.Count} / 1000행" + (observer.Skipped > 0 ? $" · 누락 {observer.Skipped}" : "");
        ObservationEmpty.Visibility = observations.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var row = ObservationGrid.SelectedItem as ObservedConnection;
        var proxy = ProxyBox.SelectedItem as ProxyServer;
        string? reason = saving ? "설정을 저장하는 중입니다." : !CanEdit ? "규칙 적용 중에는 규칙을 추가할 수 없습니다. [■ 적용 중지] 후 추가하세요(모니터는 계속 켜 둘 수 있음)."
            : SelectedAction == RuleAction.Proxy && proxy is null ? "PROXY 규칙에는 서버가 필요합니다. 먼저 ①에서 [+ 서버 추가]를 누르세요."
            : row is null ? "위 목록에서 연결(행)을 하나 선택하세요."
            : !row.CanRoute ? "로컬·멀티캐스트·IPv6 링크로컬 연결은 규칙으로 보낼 수 없습니다."
            : OnlyObservedProgram.IsChecked == true && row.ProcessName is null ? "프로그램 이름을 알 수 없습니다. 새 연결을 다시 잡거나 '이 프로그램만'을 해제하세요."
            : SelectedAction == RuleAction.Proxy && proxy?.Kind == ProxyKind.Http && row.Network == Transport.Udp ? "UDP 연결은 SOCKS5 서버로만 보낼 수 있습니다." : null;
        AddObservedButton.IsEnabled = reason is null;
        AddObservedButton.ToolTip = reason ?? $"선택한 연결로 {SelectedAction.ToString().ToUpperInvariant()} 규칙을 추가합니다(동작은 ②, 서버는 ①에서 선택한 값).";
    }
    private async void AddObservedRule(object sender, RoutedEventArgs e) => await AddObservedRuleAsync();
    internal async Task AddObservedRuleAsync()
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
                if (!profile.Rules[index].Enabled && !await ChangeAsync(p => p.Rules[index].Enabled = true)) return;
                QueueLog(ExistingRuleMessage);
            }
            else
            {
                if (!await ChangeAsync(p => p.Rules.Add(rule))) return;
                index = profile.Rules.Count - 1;
                QueueLog("규칙 추가: " + Describe(rule));
            }
            SelectRule(index);
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
    internal async Task VerifyDomainBindingsAsync()
    {
        if (!smokeMode) throw new InvalidOperationException();
        var count = profile.Rules.Count;
        ActionBox.SelectedIndex = (int)RuleAction.Direct;
        TargetBox.Text = "fixture.example, 203.0.113.10"; PortBox.Text = "443";
        await AddTargetAsync();
        if (profile.Rules.Count != count + 1 || !profile.Rules[^1].Destinations.Contains("203.0.113.10")
            || profile.Rules[^1].Destinations.Contains("fixture.example") || RuleParser.Networks(profile.Rules[^1].Destinations).Length < 2
            || !ToggleButton.IsEnabled || !EditorPanel.IsEnabled)
            throw new InvalidOperationException("Domain quick-add / editor state restoration failed.");
    }
    internal void VerifySmokeBindings()
    {
        if (!smokeMode) throw new InvalidOperationException();
        if (RuleEmpty.Visibility != Visibility.Visible || !RuleHint.Text.Contains("서버가 필요")) throw new InvalidOperationException("Getting-started guide or missing-server hint not shown.");
        _ = ChangeAsync(p => { p.Proxies.Add(new ProxyServer { Id = "sample", Name = "Local SOCKS5", Host = "127.0.0.1" }); p.Proxies.Add(new ProxyServer { Id = "burp", Name = "Burp · 127.0.0.1:8080", Host = "127.0.0.1", Port = 8080, Kind = ProxyKind.Http }); }, "burp");
        if (!RuleHint.Text.Contains("TCP만")) throw new InvalidOperationException("Selected HTTP proxy hint not shown.");
        TargetBox.Text = "203.0.113.10"; PortBox.Text = "443"; ProcessBox.Text = "chrome.exe"; AddTarget(this, new RoutedEventArgs());
        ProxyBox.SelectedValue = "sample"; TargetBox.Text = "2001:db8::/32"; PortBox.Text = "5000-5100"; ProcessBox.Text = ""; ProtocolBox.SelectedIndex = 1; AddTarget(this, new RoutedEventArgs());
        if (RulesGrid.Items.Count != 2 || !ToggleButton.IsEnabled || RuleEmpty.Visibility == Visibility.Visible) throw new InvalidOperationException("GUI bindings failed.");
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
        var countBeforeDuplicate = profile.Rules.Count;
        TargetBox.Text = "198.51.100.20"; AddTarget(this, new RoutedEventArgs());
        if (profile.Rules.Count != countBeforeDuplicate || RulesGrid.SelectedIndex != countBeforeDuplicate - 1) throw new InvalidOperationException("Quick-add duplicated an identical rule.");
        if (Icon is null) throw new InvalidOperationException("Application icon not loaded.");
        RulesGrid.SelectedIndex = profile.Rules.Count - 1; RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
        ProtocolBox.SelectedIndex = 0; ActionBox.SelectedIndex = (int)RuleAction.Proxy;
        TargetBox.Text = "*"; PortBox.Text = "*"; ProcessBox.Text = "worker.exe"; ProtocolBox.SelectedIndex = 2;
        AddTarget(this, new RoutedEventArgs());
        if (profile.Rules[^1].Destinations != "*" || profile.Rules[^1].ProcessName != "worker.exe") throw new InvalidOperationException("Process-only wildcard rule failed.");
        ProcessBox.Text = ""; ProtocolBox.SelectedIndex = 0;
        TargetBox.Text = "203.0.113.10, 198.51.100.20"; PortBox.Text = "80, 443, 8000-9000";
        var countBeforeLists = profile.Rules.Count;
        AddTarget(this, new RoutedEventArgs());
        if (profile.Rules.Count != countBeforeLists + 1 || profile.Rules[^1].Destinations != "203.0.113.10, 198.51.100.20"
            || profile.Rules[^1].Ports != "80, 443, 8000-9000") throw new InvalidOperationException("Comma-separated quick-add failed.");
        // 값이 같은 중복 규칙(파일 직접 편집 등): 선택한 행 자체가 이동·토글되어야 한다.
        var twin = new RoutingRule { Name = "twin", Destinations = "198.51.100.77", Ports = "443", Action = RuleAction.Direct };
        _ = ChangeAsync(p => { p.Rules.Add(twin with { }); p.Rules.Add(twin with { }); });
        RulesGrid.SelectedIndex = profile.Rules.Count - 1; MoveRule(-1);
        if (profile.Rules[^3].Name == "twin" || RulesGrid.SelectedIndex != profile.Rules.Count - 2) throw new InvalidOperationException("Moving a duplicate rule moved the wrong row.");
        ToggleRule(new CheckBox { DataContext = (RuleRow)RulesGrid.Items[profile.Rules.Count - 1], IsChecked = false }, new RoutedEventArgs());
        if (!profile.Rules[^2].Enabled || profile.Rules[^1].Enabled) throw new InvalidOperationException("Toggling a duplicate rule changed the wrong row.");
        _ = ChangeAsync(p => p.Rules.RemoveRange(p.Rules.Count - 2, 2));
        RulesGrid.SelectedIndex = profile.Rules.Count - 1; RulesGrid.ScrollIntoView(RulesGrid.SelectedItem);
        TargetBox.Text = ""; PortBox.Text = "*"; ActionBox.SelectedIndex = (int)RuleAction.Proxy;
    }
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (closed) return; e.Cancel = true; if (closing) return;
        closing = true; lifetime.Cancel(); IsEnabled = false;
        try { try { await observer.DisposeAsync(); } finally { await engine.DisposeAsync(); } } catch (Exception ex) { Error(ex); }
        finally
        {
            if (cleanupGuard is not null)
                try { await cleanupGuard; } catch (Exception ex) { QueueLog($"정리 도우미를 사용할 수 없습니다: {ex.GetType().Name}."); }
            // 진행 중인 설정 저장이 끝난 뒤에 창을 닫는다(실패 안내는 ChangeAsync가 이미 처리).
            if (pendingSave is { } save) try { await save; } catch (Exception) { }
            await UnloadDriverAsync(); timer.Stop();
            // Idle cleanup can finish synchronously. Let the cancelled Closing
            // event unwind before requesting another close from the dispatcher.
            await Dispatcher.Yield(DispatcherPriority.Background);
            closed = true; Close();
        }
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
