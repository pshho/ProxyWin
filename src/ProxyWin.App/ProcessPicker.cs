using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;

namespace ProxyWin.App;

internal static class ProcessPicker
{
    private sealed class State { public string[] Names = []; public bool Updating; public DispatcherOperation? Pending; }
    private static readonly ConditionalWeakTable<ComboBox, State> states = new();

    public static void Attach(ComboBox box)
    {
        if (states.TryGetValue(box, out _)) return;
        var state = new State(); states.Add(box, state);
        box.AddHandler(TextBoxBase.TextChangedEvent, new TextChangedEventHandler((_, _) =>
        {
            if (state.Updating || !box.IsKeyboardFocusWithin) return;
            state.Pending?.Abort();
            // TextChanged occurs before WPF finishes moving the caret for this keystroke.
            // Never replace the item source or restore selection inside that edit transaction.
            state.Pending = box.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                state.Pending = null;
                if (!box.IsKeyboardFocusWithin || state.Updating) return;
                if (state.Names.Length == 0) state.Names = RunningNames();
                var editor = box.Template?.FindName("PART_EditableTextBox", box) as TextBox;
                Apply(box, editor?.Text ?? box.Text, open: true);
            }));
        }), handledEventsToo: true);
    }

    public static void Refresh(ComboBox box)
    {
        Attach(box); var state = states.GetValue(box, _ => new State());
        if (state.Updating) return;
        state.Names = RunningNames();
        Search(box, box.Text);
    }
    internal static string[] Filter(IEnumerable<string> names, string query) => names
        .Where(n => n.Contains(query.Trim(), StringComparison.OrdinalIgnoreCase))
        .OrderBy(n => n.StartsWith(query.Trim(), StringComparison.OrdinalIgnoreCase) ? 0 : 1)
        .ThenBy(n => n, StringComparer.OrdinalIgnoreCase).ToArray();

    public static void Search(ComboBox box, string query) => Apply(box, query, open: false);

    private static void Apply(ComboBox box, string query, bool open)
    {
        Attach(box); var state = states.GetValue(box, _ => new State());
        if (state.Updating) return;
        var editor = box.Template?.FindName("PART_EditableTextBox", box) as TextBox;
        var selectionStart = editor?.Text == query ? editor.SelectionStart : query.Length;
        var selectionLength = editor?.Text == query ? editor.SelectionLength : 0;
        var selected = box.SelectedItem as string;
        state.Updating = true;
        try
        {
            var choices = Filter(state.Names, query);
            if (!box.Items.Cast<string>().SequenceEqual(choices)) box.ItemsSource = choices;
            if (box.Text != query) box.Text = query;
            if (open && !box.IsDropDownOpen && !string.Equals(selected, query, StringComparison.OrdinalIgnoreCase)) box.IsDropDownOpen = true;
            if (editor is not null)
            {
                if (editor.Text != query) editor.Text = query;
                var start = Math.Min(selectionStart, query.Length);
                editor.Select(start, Math.Min(selectionLength, query.Length - start));
            }
        }
        finally { state.Updating = false; }
    }

    private static string[] RunningNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { var name = process.ProcessName; if (!string.IsNullOrEmpty(name)) names.Add(name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe"); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            }
        }
        return names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
