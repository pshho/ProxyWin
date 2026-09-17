using System.Windows;
using ProxyWin.Core;

namespace ProxyWin.App;

public partial class RuleDialog : Window
{
    private readonly List<ProxyServer> proxies;
    private readonly string name;
    public RoutingRule? Result { get; private set; }
    public RuleDialog(RoutingRule? rule, List<ProxyServer> proxies)
    {
        InitializeComponent();
        ProcessPicker.Attach(ProcessBox);
        this.proxies = proxies;
        rule ??= new RoutingRule { Destinations = "*", Action = proxies.Count > 0 ? RuleAction.Proxy : RuleAction.Direct, ProxyId = proxies.FirstOrDefault()?.Id ?? "direct" };
        name = rule.Name;
        DestinationsBox.Text = rule.Destinations;
        PortsBox.Text = rule.Ports;
        NetworkBox.SelectedIndex = (int)rule.Network;
        TargetBox.ItemsSource = proxies;
        TargetBox.SelectedValue = rule.ProxyId;
        EnabledBox.IsChecked = rule.Enabled;
        ProcessBox.Text = rule.ProcessName;
        ActionBox.SelectedIndex = (int)rule.Action;
        TargetBox.IsEnabled = rule.Action == RuleAction.Proxy;
    }
    private void Save(object sender, RoutedEventArgs e)
    {
        try
        {
            var result = new RoutingRule
            {
                Name = name, Destinations = DestinationsBox.Text.Trim(), Ports = PortsBox.Text.Trim(),
                Network = (Transport)NetworkBox.SelectedIndex, Enabled = EnabledBox.IsChecked == true,
                Action = (RuleAction)ActionBox.SelectedIndex,
                ProxyId = ActionBox.SelectedIndex == (int)RuleAction.Proxy ? TargetBox.SelectedValue as string ?? "" : ActionBox.SelectedIndex == (int)RuleAction.Direct ? "direct" : "block", ProcessName = ProcessBox.Text.Trim()
            };
            RuleParser.Validate(new Profile { Proxies = proxies, Rules = [result] });
            Result = result;
            DialogResult = true;
        }
        catch (Exception ex) { AppMessages.Error(this, ex); }
    }
    private void OpenProcessPicker(object sender, EventArgs e)
    {
        try { ProcessPicker.Refresh(ProcessBox); }
        catch (Exception ex) { AppMessages.Error(this, ex); }
    }
    private void ActionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (IsInitialized) TargetBox.IsEnabled = ActionBox.SelectedIndex == (int)RuleAction.Proxy;
    }
}
