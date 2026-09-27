using CommandLine;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using ThreatCheck.Scanners;

namespace ThreatCheck;

internal static class Program
{
    private class Options
    {
        [Option('e', "engine", Default = "Defender", Required = false, HelpText = "Scanning engine. Options: Defender, AMSI")]
        public string Engine { get; set; }

        [Option('f', "file", Required = false, HelpText = "Analyze a file on disk")]
        public string InFile { get; set; }

        [Option('u', "url", Required = false, HelpText = "Analyze a file from a URL")]
        public string InUrl { get; set; }

        [Option('t', "type", Default = "Bin", Required = false, HelpText = "File type to scan. Options: Bin, Script")]
        public string FileType { get; set; }
    }

    private enum ScanningEngine
    {
        Defender,
        Amsi
    }

    private static void Main(string[] args)
    {
        var watch = Stopwatch.StartNew();

        Parser.Default.ParseArguments<Options>(args)
            .WithParsed(RunOptions)
            .WithNotParsed(HandleParseError);

        watch.Stop();

#if DEBUG
        CustomConsole.WriteDebug($"Run time: {Math.Round(watch.Elapsed.TotalSeconds, 2)}s");
#endif
    }

    private static void RunOptions(Options opts)
    {
        byte[] fileContent = null;
        string scriptContent = null;

        var engine = (ScanningEngine)Enum.Parse(typeof(ScanningEngine), opts.Engine, true);

        if (!string.IsNullOrEmpty(opts.InUrl))
        {
            try
            {
                fileContent = DownloadFile(opts.InUrl);
            }
            catch
            {
                CustomConsole.WriteError("Could not connect to URL");
                return;
            }

        }
        else if (!string.IsNullOrEmpty(opts.InFile))
        {
            if (File.Exists(opts.InFile) && opts.FileType.Equals("Bin", StringComparison.OrdinalIgnoreCase))
            {
                fileContent = File.ReadAllBytes(opts.InFile);
            }
            else if (File.Exists(opts.InFile) && opts.FileType.Equals("Script", StringComparison.OrdinalIgnoreCase))
            {
                scriptContent = File.ReadAllText(opts.InFile);
            }
            else
            {
                CustomConsole.WriteError("File not found");
                return;
            }
        }
        else
        {
            CustomConsole.WriteError("File or URL required");
            return;
        }

        switch (engine)
        {
            case ScanningEngine.Defender:
            {
                if (fileContent is not null)
                {
                    ScanWithDefender(fileContent);
                }
                else
                {
                    Console.WriteLine("Scripts don't work with Defender yet");
                }

                break;
            }

            case ScanningEngine.Amsi:
            {
                if (fileContent is not null)
                {
                    ScanWithAmsi(fileContent);
                }
                else
                {
                    ScanWithAmsi(scriptContent);
                }

                break;
            }

            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private static void HandleParseError(IEnumerable<Error> errs)
    {
        foreach (var err in errs)
            Console.Error.WriteLine(err.ToString());
    }

    private static byte[] DownloadFile(string url)
    {
        using var client = new WebClient();
        return client.DownloadData(url);
    }

    private static void ScanWithDefender(byte[] file)
    {
        var defender = new DefenderScanner(file);
        defender.AnalyzeFile();
    }

    private static void ScanWithAmsi(byte[] file)
    {
        using var amsi = new AmsiScanner();

        if (!amsi.RealTimeProtectionEnabled)
        {
            CustomConsole.WriteError("Ensure real-time protection is enabled");
            return;
        }

        amsi.AnalyzeBytes(file);
    }

    // There was an issue with the way bytes were converted when using File.ReadAllBytes
    // which caused the bytes to not properly match signatures compared to when being executed. 
    // The string has be decoded from unicode in order to get proper detections 
    private static void ScanWithAmsi(string file)
    {

        var fileBytes = Encoding.Unicode.GetBytes(file);
        using var amsi = new AmsiScanner();

        if (!amsi.RealTimeProtectionEnabled)
        {
            CustomConsole.WriteError("Ensure real-time protection is enabled");
            return;
        }

        amsi.AnalyzeBytes(fileBytes);
    }
}