using System.Windows;
using System.Windows.Controls;
using ProxyWin.Core;

namespace ProxyWin.App;

public partial class ProxyDialog : Window
{
    private const string BurpName = "Burp Suite", SocksName = "로컬 SOCKS5";
    private readonly string id;
    private readonly bool ready;
    public ProxyServer? Result { get; private set; }
    public ProxyDialog(ProxyServer? proxy)
    {
        InitializeComponent();
        var isNew = proxy is null;
        proxy ??= new ProxyServer();
        id = proxy.Id;
        // 새 서버는 이름을 비워 두고 저장 시 종류·주소로 자동 이름을 붙인다.
        NameBox.Text = isNew ? "" : proxy.Name;
        HostBox.Text = proxy.Host;
        PortBox.Text = proxy.Port.ToString();
        KindBox.SelectedIndex = proxy.Kind == ProxyKind.Socks5 ? 0 : 1;
        UserBox.Text = proxy.Username;
        PasswordBox.Password = proxy.Password;
        Loaded += (_, _) => (isNew ? HostBox : NameBox).Focus();
        ready = true;
    }
    private ProxyKind SelectedKind => KindBox.SelectedIndex == 0 ? ProxyKind.Socks5 : ProxyKind.Http;
    private static int DefaultPort(ProxyKind kind) => kind == ProxyKind.Socks5 ? 1080 : 8080;
    private void UseBurp(object sender, RoutedEventArgs e) => Fill(BurpName, ProxyKind.Http, 8080);
    private void UseSocks(object sender, RoutedEventArgs e) => Fill(SocksName, ProxyKind.Socks5, 1080);
    private void Fill(string name, ProxyKind kind, int port)
    {
        if (NameBox.Text.Trim() is "" or BurpName or SocksName) NameBox.Text = name;
        KindBox.SelectedIndex = kind == ProxyKind.Socks5 ? 0 : 1;
        HostBox.Text = "127.0.0.1"; PortBox.Text = port.ToString();
        PortBox.Focus(); PortBox.SelectAll();
    }
    private void KindChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ready) return;
        // 포트를 직접 바꾸지 않았다면(비었거나 다른 종류의 기본값) 종류에 맞는 기본 포트로 바꾼다.
        if (PortBox.Text.Trim() is "" or "1080" or "8080") PortBox.Text = DefaultPort(SelectedKind).ToString();
    }
    private void Save(object sender, RoutedEventArgs e)
    {
        try
        {
            var host = HostBox.Text.Trim();
            if (host.Length == 0) throw new FormatException("호스트를 입력하세요. 이 PC에서 실행 중인 Burp/SOCKS5라면 127.0.0.1 입니다.");
            if (host.Contains("://")) throw new FormatException("호스트에는 http:// 없이 주소만 입력하세요. 예: 127.0.0.1");
            if (!int.TryParse(PortBox.Text.Trim(), out var port)) throw new FormatException("포트에 숫자를 입력하세요. 예: Burp 8080, SOCKS5 1080");
            var result = new ProxyServer
            {
                Id = id, Name = NameBox.Text.Trim(), Host = host, Port = port, Kind = SelectedKind,
                Username = UserBox.Text, Password = PasswordBox.Password
            };
            if (result.Name.Length == 0) result.Name = $"{(result.Kind == ProxyKind.Socks5 ? "SOCKS5" : "HTTP")} {result.Endpoint}";
            RuleParser.Validate(new Profile { Proxies = [result] });
            Result = result;
            DialogResult = true;
        }
        catch (Exception ex) { AppMessages.Error(this, ex); }
    }
}
