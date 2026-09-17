using System.IO;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Runtime.InteropServices;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args is ["--check-exe", var executable])
        {
            var count = ExtractIconEx(executable, -1, IntPtr.Zero, IntPtr.Zero, 0);
            if (count == 0) throw new InvalidDataException("Executable has no native icon resource.");
            Console.WriteLine($"Executable native icon resources: {count}"); return 0;
        }
        if (args.Length != 2) throw new ArgumentException("Usage: IconBuilder drawing.xaml output-directory");
        using var input = File.OpenRead(args[0]);
        var image = (DrawingImage)XamlReader.Load(input);
        var frames = new List<(int Size, byte[] Png)>();
        Directory.CreateDirectory(args[1]);
        foreach (var size in new[] { 16, 24, 32, 48, 64, 128, 256 })
        {
            var visual = new DrawingVisual();
            using (var drawing = visual.RenderOpen()) drawing.DrawImage(image, new Rect(0, 0, size, size));
            var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream = new MemoryStream(); encoder.Save(stream);
            frames.Add((size, stream.ToArray()));
        }
        File.WriteAllBytes(Path.Combine(args[1], "ProxyWin.png"), frames[^1].Png);
        using (var file = File.Create(Path.Combine(args[1], "ProxyWin.ico")))
        using (var writer = new BinaryWriter(file))
        {
            writer.Write((ushort)0); writer.Write((ushort)1); writer.Write((ushort)frames.Count);
            var offset = 6 + 16 * frames.Count;
            foreach (var frame in frames)
            {
                writer.Write((byte)(frame.Size == 256 ? 0 : frame.Size)); writer.Write((byte)(frame.Size == 256 ? 0 : frame.Size));
                writer.Write((byte)0); writer.Write((byte)0); writer.Write((ushort)1); writer.Write((ushort)32);
                writer.Write(frame.Png.Length); writer.Write(offset); offset += frame.Png.Length;
            }
            foreach (var frame in frames) writer.Write(frame.Png);
        }
        Console.WriteLine("Generated 7-size ICO (16–256 px) and PNG from the vector drawing.");
        return 0;
    }
    [DllImport("shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconEx(string file, int index, IntPtr large, IntPtr small, uint count);
}
