using System.Diagnostics;
using System.Globalization;
using System.Reflection;

namespace ProxyWin.Windows;

public static class DriverCleanupGuard
{
    public static Task StartAsync(string directory) => Task.Run(() =>
    {
        Directory.CreateDirectory(directory);
        var eventName = @"Local\ProxyWin.Cleanup." + Guid.NewGuid().ToString("N");
        using var ready = new EventWaitHandle(false, EventResetMode.ManualReset, eventName);
        using var parent = Process.GetCurrentProcess();
        var executable = Environment.ProcessPath ?? throw new IOException("프로그램 실행 파일 위치를 찾을 수 없습니다.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
        foreach (var argument in new[] { "--driver-cleanup", parent.Id.ToString(CultureInfo.InvariantCulture),
            parent.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture), eventName, Path.Combine(directory, "driver-cleanup.txt") })
            start.ArgumentList.Add(argument);
        using var child = Process.Start(start) ?? throw new IOException("드라이버 정리 도우미를 시작할 수 없습니다.");
        if (!ready.WaitOne(TimeSpan.FromSeconds(10)))
        {
            if (!child.HasExited) { child.Kill(); child.WaitForExit(3000); }
            throw new IOException("드라이버 정리 도우미가 시작되지 않았습니다. 프로그램 파일이 온전한지 확인하세요.");
        }
    });

    // A separate process survives termination of the GUI alone. It does not keep
    // a driver handle open, and never kills applications using the shared driver.
    public static async Task<int> RunAsync(string pidText, string ticksText, string eventName, string reportPath)
    {
        try
        {
            using var parent = Process.GetProcessById(int.Parse(pidText, CultureInfo.InvariantCulture));
            if (parent.StartTime.ToUniversalTime().Ticks != long.Parse(ticksText, CultureInfo.InvariantCulture)) return 2;
            using (var ready = EventWaitHandle.OpenExisting(eventName)) ready.Set();
            await parent.WaitForExitAsync();
            var result = await DriverService.TryUnloadAsync();
            File.WriteAllText(reportPath, $"{DateTimeOffset.Now:O} {result.Message}{Environment.NewLine}");
            return result.Unloaded ? 0 : 1;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or WaitHandleCannotBeOpenedException)
        { return 2; }
    }
}
