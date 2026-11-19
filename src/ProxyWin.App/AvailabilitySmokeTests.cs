using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using ProxyWin.Core;

namespace ProxyWin.App;

public partial class MainWindow
{
    // The smoke runner supplies an isolated profile and opens no driver handles.
    internal async Task VerifySaveFailuresAsync()
    {
        lifetime.Cancel(); // 저장 실패 검증만 다루므로 진행 중인 비동기 작업과 분리한다.
        var observed = new ObservedConnection(DateTimeOffset.Now, 123, "fixture.exe", IPAddress.Parse("192.0.2.1"),
            51000, IPAddress.Parse("203.0.113.11"), 443, Transport.Tcp, false);
        var disabled = observed.CreateRule("", true, RuleAction.Block) with { Enabled = false };
        profile = new Profile { Rules = [new RoutingRule { Destinations = "203.0.113.10", Action = RuleAction.Block }, disabled] };
        store.Save(profile); Refresh(); Show();
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        RulesGrid.UpdateLayout();
        static CheckBox? FindCheck(DependencyObject node)
        {
            if (node is CheckBox check) return check;
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(node); i++)
                if (FindCheck(VisualTreeHelper.GetChild(node, i)) is { } child) return child;
            return null;
        }
        var check = FindCheck((DependencyObject)RulesGrid.ItemContainerGenerator.ContainerFromIndex(0))
            ?? throw new InvalidOperationException("Rule checkbox was not rendered.");
        var errors = new List<string>();
        var dismissed = 0;
        // 저장은 백그라운드에서 실패하므로, 오류 창이 실제로 뜰 때까지(최대 10초) 기다렸다가 닫는다.
        void DismissExpectedError()
        {
            var deadline = Environment.TickCount64 + 10000;
            void Attempt() => Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
            {
                var dialog = Application.Current.Windows.Cast<Window>().SingleOrDefault(w => w.Owner == this && w.Title == "ProxyWin");
                if (dialog is null) { if (Environment.TickCount64 < deadline) Attempt(); return; }
                dismissed++; dialog.Close();
            }));
            Attempt();
        }
        var path = Path.Combine(store.DirectoryPath, "profile.dat");
        var saved = File.ReadAllBytes(path);
        // A real Windows sharing violation tests atomic-save failure, not a mocked exception.
        using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            check.SetCurrentValue(CheckBox.IsCheckedProperty, false);
            DismissExpectedError(); await ToggleRuleAsync(check);
            if (!profile.Rules[0].Enabled || check.IsChecked != true)
                errors.Add("Failed save left the rule checkbox inconsistent with the unchanged profile.");
            ActionBox.SelectedIndex = (int)RuleAction.Block;
            AddObservation(observed); ObservationGrid.SelectedItem = observed;
            pendingLogs.Clear(); logs.Clear();
            DismissExpectedError(); await AddObservedRuleAsync();
            if (profile.Rules[1].Enabled || pendingLogs.Concat(logs).Any(line => line.Contains(ExistingRuleMessage, StringComparison.Ordinal)))
                errors.Add("Failed observed-rule save reported success or changed the profile.");
            if (!File.ReadAllBytes(path).SequenceEqual(saved)) errors.Add("Failed save changed the encrypted profile.");
            if (Directory.EnumerateFiles(store.DirectoryPath, "*.tmp").Any()) errors.Add("Failed save left a temporary file.");
        }
        if (dismissed != 2) errors.Add("Expected two actual save-error dialogs.");
        // After the sharing violation ends, editing and persistence must recover.
        check.SetCurrentValue(CheckBox.IsCheckedProperty, false);
        await ToggleRuleAsync(check);
        if (profile.Rules[0].Enabled || store.Load().Rules[0].Enabled) errors.Add("Editing did not recover after the file was unlocked.");
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Closed += (_, _) => finished.TrySetResult();
        Close();
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (errors.Count > 0) throw new InvalidOperationException(string.Join("\n", errors));
    }
}
