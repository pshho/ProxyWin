using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public sealed class ProfileStore(string directory)
{
    public static string DefaultDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProxyWin");
    private string FilePath => Path.Combine(directory, "profile.dat");

    public Profile Load()
    {
        if (!File.Exists(FilePath)) return new Profile();
        var bytes = Protect(File.ReadAllBytes(FilePath), decrypt: true);
        try
        {
            var profile = JsonSerializer.Deserialize<Profile>(bytes) ?? throw new FormatException("Profile is empty.");
            RuleParser.Validate(profile);
            profile.Version = 2;
            return profile;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void Save(Profile profile)
    {
        RuleParser.Validate(profile);
        Directory.CreateDirectory(directory);
        // Old applications reject version 2 instead of silently treating BLOCK as DIRECT.
        var persisted = new Profile { Version = 2, Proxies = profile.Proxies, Rules = profile.Rules };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(persisted);
        try
        {
            var encrypted = Protect(bytes, decrypt: false);
            var temporary = Path.Combine(directory, $"{Guid.NewGuid():N}.tmp");
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    file.Write(encrypted);
                    file.Flush(flushToDisk: true);
                }
                File.Move(temporary, FilePath, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] Protect(byte[] input, bool decrypt)
    {
        var pin = GCHandle.Alloc(input, GCHandleType.Pinned);
        var blob = new Blob { Size = input.Length, Data = pin.AddrOfPinnedObject() };
        Blob output = default;
        try
        {
            var success = decrypt
                ? CryptUnprotectData(ref blob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptProtectData(ref blob, "ProxyWin", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read or save the Windows-protected profile.");
            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                for (var i = 0; i < output.Size; i++) Marshal.WriteByte(output.Data, i, 0);
                LocalFree(output.Data);
            }
            pin.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
