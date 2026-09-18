using System.Diagnostics;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text.Json;

internal sealed class WhaleClient : IAsyncDisposable
{
    private readonly ClientWebSocket socket = new();
    private Process process;
    public Process Process => process;
    private int sequence;
    private WhaleClient(Process process) { this.process = process; }
    public static async Task<WhaleClient> Start(string executable, string directory)
    {
        Directory.CreateDirectory(directory);
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        foreach (var argument in new[] { "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-quic", "--proxy-server=direct://", "--remote-debugging-port=0", "--user-data-dir=" + directory, "about:blank" }) start.ArgumentList.Add(argument);
        var client = new WhaleClient(Process.Start(start)!);
        try
        {
            var path = Path.Combine(directory, "DevToolsActivePort");
            await Wait.Until(() => File.Exists(path) && new FileInfo(path).Length > 0, "Whale DevTools endpoint", 30);
            var lines = await File.ReadAllLinesAsync(path);
            // Whale's launcher can exit after spawning the real browser. Track the
            // browser owning this isolated DevTools endpoint, not the launcher PID.
            using (var browser = new ClientWebSocket())
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await browser.ConnectAsync(new Uri($"ws://127.0.0.1:{int.Parse(lines[0])}{lines[1]}"), timeout.Token);
                await browser.SendAsync(JsonSerializer.SerializeToUtf8Bytes(new { id = 1, method = "SystemInfo.getProcessInfo" }), WebSocketMessageType.Text, true, timeout.Token);
                var buffer = new byte[65536];
                using var data = new MemoryStream();
                WebSocketReceiveResult response;
                do { response = await browser.ReceiveAsync(buffer, timeout.Token); data.Write(buffer, 0, response.Count); } while (!response.EndOfMessage);
                using var information = JsonDocument.Parse(data.ToArray());
                var browserId = information.RootElement.GetProperty("result").GetProperty("processInfo").EnumerateArray()
                    .Single(p => p.GetProperty("type").GetString() == "browser").GetProperty("id").GetInt32();
                if (browserId != client.process.Id) { client.process.Dispose(); client.process = Process.GetProcessById(browserId); }
            }
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            using var tabs = JsonDocument.Parse(await http.GetStringAsync($"http://127.0.0.1:{int.Parse(lines[0])}/json/list"));
            var tab = tabs.RootElement.EnumerateArray().First(t => t.GetProperty("type").GetString() == "page");
            await client.socket.ConnectAsync(new Uri(tab.GetProperty("webSocketDebuggerUrl").GetString()!), CancellationToken.None);
            return client;
        }
        catch { await client.DisposeAsync(); throw; }
    }
    public async Task<JsonElement> Command(string method, object arguments)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var id = ++sequence;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { id, method, @params = arguments });
        await socket.SendAsync(bytes, WebSocketMessageType.Text, true, timeout.Token);
        var buffer = new byte[65536];
        while (true)
        {
            using var output = new MemoryStream();
            WebSocketReceiveResult received;
            do { received = await socket.ReceiveAsync(buffer, timeout.Token); output.Write(buffer, 0, received.Count); } while (!received.EndOfMessage);
            using var message = JsonDocument.Parse(output.ToArray());
            if (!message.RootElement.TryGetProperty("id", out var responseId) || responseId.GetInt32() != id) continue;
            if (message.RootElement.TryGetProperty("error", out var error)) throw new IOException("CDP: " + error);
            return message.RootElement.GetProperty("result").Clone();
        }
    }
    public async Task<JsonElement> Evaluate(string expression)
    {
        var result = await Command("Runtime.evaluate", new { expression, awaitPromise = true, returnByValue = true });
        if (result.TryGetProperty("exceptionDetails", out var error)) throw new IOException("Whale evaluation: " + error);
        return result.GetProperty("result").TryGetProperty("value", out var value) ? value.Clone() : default;
    }
    public async Task<double> Transfer(string origin, int bytes = 1048576)
    {
        var url = JsonSerializer.Serialize($"{origin}/bytes/{bytes}?id={Guid.NewGuid():N}");
        var result = await Evaluate($$"""
            (async()=>{const t=performance.now(); const r=await fetch({{url}}, {cache:'no-store',signal:AbortSignal.timeout(15000)});
            if(!r.ok)throw Error('HTTP '+r.status); const b=new Uint8Array(await r.arrayBuffer()); const ms=performance.now()-t;
            if(b.length!=={{bytes}})throw Error('length '+b.length); for(let i=0;i<b.length;i++)if(b[i]!==i%251)throw Error('payload '+i);
            return ms;})()
            """);
        return result.GetDouble();
    }
    public async ValueTask DisposeAsync()
    {
        socket.Dispose();
        if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
        process.Dispose();
    }
}

internal static class Wait
{
    public static async Task Until(Func<bool> condition, string description, int seconds = 10)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition())
        {
            if (deadline.Elapsed.TotalSeconds >= seconds) throw new TimeoutException(description);
            await Task.Delay(50);
        }
    }
}
