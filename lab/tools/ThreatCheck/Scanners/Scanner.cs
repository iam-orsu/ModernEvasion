using System;

namespace ThreatCheck.Scanners;

// There was an issue with array handling when scanning small scripts. ChatGPT fixed it
internal abstract class Scanner
{
    protected static bool Malicious = false;
    protected static bool Complete = false;

    protected virtual byte[] HalfSplitter(byte[] originalArray, int lastGood)
    {
        var splitSize = (originalArray.Length - lastGood) / 2 + lastGood;
        var splitArray = new byte[splitSize];

        if (originalArray.Length == splitSize + 1)
        {
            var msg = $"Identified end of bad bytes at offset 0x{originalArray.Length:X}";
            CustomConsole.WriteThreat(msg);

            var offendingSize = Math.Min(originalArray.Length, 256);
            var offendingBytes = new byte[offendingSize];
            Buffer.BlockCopy(originalArray, originalArray.Length - offendingSize, offendingBytes, 0, offendingSize);

            Helpers.HexDump(offendingBytes, originalArray.Length);
            Complete = true;
        }

        Array.Copy(originalArray, splitArray, splitArray.Length);
        return splitArray;
    }

    protected virtual byte[] Overshot(byte[] originalArray, int splitArraySize)
    {
        var newSize = (originalArray.Length - splitArraySize) / 2 + splitArraySize;

        if (newSize == originalArray.Length - 1)
        {
            Complete = true;

            if (Malicious)
            {
                CustomConsole.WriteError("File is malicious, but couldn't identify bad bytes");
            }
        }

        var newArray = new byte[newSize];
        Buffer.BlockCopy(originalArray, 0, newArray, 0, newSize);

        return newArray;
    }
}