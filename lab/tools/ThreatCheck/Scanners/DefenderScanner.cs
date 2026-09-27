using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace ThreatCheck.Scanners;

internal sealed class DefenderScanner : Scanner
{
    private readonly byte[] _fileBytes;
    private string _filePath;

    public DefenderScanner(byte[] file)
    {
        _fileBytes = file;
    }

    public void AnalyzeFile()
    {
        if (!Directory.Exists(@"C:\Temp"))
        {
#if DEBUG
            CustomConsole.WriteDebug(@"C:\Temp doesn't exist. Creating it...");
#endif
            Directory.CreateDirectory(@"C:\Temp");
        }

        _filePath = Path.Combine(@"C:\Temp", "file.exe");
        File.WriteAllBytes(_filePath, _fileBytes);

        var status = ScanFile(_filePath);

        if (status.Result is ScanResult.NoThreatFound)
        {
            CustomConsole.WriteOutput("No threat found!");
            return;
        }

        Malicious = true;

        CustomConsole.WriteOutput($"Target file size: {_fileBytes.Length} bytes");
        CustomConsole.WriteOutput("Analyzing...");

        var splitArray = new byte[_fileBytes.Length / 2];
        Buffer.BlockCopy(_fileBytes, 0, splitArray, 0, _fileBytes.Length / 2);
        var lastgood = 0;

        while (!Complete)
        {
#if DEBUG
            CustomConsole.WriteDebug($"Testing {splitArray.Length} bytes");
#endif
            File.WriteAllBytes(_filePath, splitArray);
            status = ScanFile(_filePath);

            if (status.Result is ScanResult.ThreatFound)
            {
#if DEBUG
                CustomConsole.WriteDebug("Threat found, splitting");
#endif
                var tmpArray = HalfSplitter(splitArray, lastgood);
                Array.Resize(ref splitArray, tmpArray.Length);
                Array.Copy(tmpArray, splitArray, tmpArray.Length);
            }
            else
            {
#if DEBUG
                CustomConsole.WriteDebug("No threat found, increasing size");
#endif
                lastgood = splitArray.Length;
                var tmpArray = Overshot(_fileBytes, splitArray.Length);
                Array.Resize(ref splitArray, tmpArray.Length);
                Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
            }
        }
    }

    private static DefenderScanResult ScanFile(string file, bool getSig = false)
    {
        var result = new DefenderScanResult();

        if (!File.Exists(file))
        {
            result.Result = ScanResult.FileNotFound;
            return result;
        }

        using var process = new Process();
        var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
        {
            Arguments = $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation -Trace -Level 0x10",
            CreateNoWindow = true,
            ErrorDialog = false,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        process.StartInfo = mpcmdrun;
        process.Start();
        process.WaitForExit(30000); // Wait 30s

        if (!process.HasExited)
        {
            process.Kill();
            result.Result = ScanResult.Timeout;
            return result;
        }

        if (getSig)
        {
            while (process.StandardOutput.ReadLine() is { } stdout)
            {
                if (!stdout.Contains("Threat  "))
                    continue;
                
                var sig = stdout.Split(' ');
                var sigName = sig[19];
                result.Signature = sigName;
                break;
            }
        }

        result.Result = process.ExitCode switch
        {
            0 => ScanResult.NoThreatFound,
            2 => ScanResult.ThreatFound,
            _ => ScanResult.Error
        };

        return result;
    }
}

public class DefenderScanResult
{
    public ScanResult Result { get; set; }
    public string Signature { get; set; }
}

public enum ScanResult
{
    [Description("No threat found")]
    NoThreatFound,
    [Description("Threat found")]
    ThreatFound,
    [Description("The file could not be found")]
    FileNotFound,
    [Description("Timeout")]
    Timeout,
    [Description("Error")]
    Error
}