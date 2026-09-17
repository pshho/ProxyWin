using System.Windows;
using ProxyWin.Core;

namespace ProxyWin.App;

public partial class ProxyDialog : Window
{
    private readonly string id;
    public ProxyServer? Result { get; private set; }
    public ProxyDialog(ProxyServer? proxy)
    {
        InitializeComponent();
        proxy ??= new ProxyServer();
        id = proxy.Id;
        NameBox.Text = proxy.Name;
        HostBox.Text = proxy.Host;
        PortBox.Text = proxy.Port.ToString();
        KindBox.SelectedIndex = proxy.Kind == ProxyKind.Socks5 ? 0 : 1;
        UserBox.Text = proxy.Username;
        PasswordBox.Password = proxy.Password;
    }
    private void Save(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!int.TryParse(PortBox.Text, out var port)) throw new FormatException("Enter a numeric port.");
            var result = new ProxyServer
            {
                Id = id, Name = NameBox.Text.Trim(), Host = HostBox.Text.Trim(), Port = port,
                Kind = KindBox.SelectedIndex == 0 ? ProxyKind.Socks5 : ProxyKind.Http,
                Username = UserBox.Text, Password = PasswordBox.Password
            };
            RuleParser.Validate(new Profile { Proxies = [result] });
            Result = result;
            DialogResult = true;
        }
        catch (Exception ex) { AppMessages.Error(this, ex); }
    }
}
