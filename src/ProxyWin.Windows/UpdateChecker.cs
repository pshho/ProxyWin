using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProxyWin.Windows;

public sealed record AvailableUpdate(Version Version, Uri ReleasePage);

public static class UpdateChecker
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(10), MaxResponseContentBufferSize = 1024 * 1024 };
    public static Task<AvailableUpdate?> CheckAsync(Version current, CancellationToken cancellationToken = default) =>
        CheckAsync(Client, current, cancellationToken);

    internal static async Task<AvailableUpdate?> CheckAsync(HttpClient client, Version current, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/repos/pshho/ProxyWin/releases/latest");
        request.Headers.UserAgent.ParseAdd($"ProxyWin/{current.Major}.{current.Minor}.{Math.Max(0, current.Build)}");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return Parse(json, current);
    }

    internal static AvailableUpdate? Parse(string json, Version current)
    {
        using var document = JsonDocument.Parse(json);
        var release = document.RootElement;
        if (release.GetProperty("draft").GetBoolean() || release.GetProperty("prerelease").GetBoolean()) return null;
        var tag = release.GetProperty("tag_name").GetString() ?? "";
        if (!Regex.IsMatch(tag, @"\Av?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant)
            || !Version.TryParse(tag.TrimStart('v'), out var latest)) throw new FormatException("Invalid release version.");
        var installed = new Version(current.Major, current.Minor, Math.Max(0, current.Build));
        // Build the link from the fixed repository, never from an API-supplied URL.
        return latest > installed ? new AvailableUpdate(latest, new Uri($"https://github.com/pshho/ProxyWin/releases/tag/{tag}")) : null;
    }
}
