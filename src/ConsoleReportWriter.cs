using System;
using System.IO;
using System.Linq;

namespace DotnetSecretsScan;

/// <summary>
/// Writes scan results as human-readable, severity color-coded text, mirroring the
/// traditional console summary output.
/// </summary>
public sealed class ConsoleReportWriter : IReportWriter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConsoleReportWriter"/> class.
    /// </summary>
    /// <param name="verbose">Whether to include per-finding details in the output.</param>
    public ConsoleReportWriter(bool verbose = false) => Verbose = verbose;

    /// <summary>
    /// Gets a value indicating whether per-finding details are included in the output.
    /// </summary>
    public bool Verbose { get; }

    /// <summary>
    /// Gets the format identifier for this writer: "console".
    /// </summary>
    public string FormatName => "console";

    /// <summary>
    /// Renders the scan result as text and writes it to <paramref name="output"/>. When
    /// <paramref name="output"/> is <see cref="Console.Out"/>, severity lines are color-coded.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        var useColor = ReferenceEquals(output, Console.Out);

        output.WriteLine($"Scan completed: {result.TotalFilesScanned} files, {result.TotalLinesScanned} lines, {result.TotalFindings} findings");
        output.WriteLine($"Timestamp: {result.ScanTimestamp:yyyy-MM-dd HH:mm:ss zzz}");
        output.WriteLine();

        if (result.TotalFindings == 0)
        {
            if (useColor)
            {
                Console.ForegroundColor = ConsoleColor.Green;
            }

            output.WriteLine("✓ No secrets found");

            if (useColor)
            {
                Console.ResetColor();
            }

            return;
        }

        // Group findings by severity
        var findingsBySeverity = result.Findings
            .GroupBy(f => f.Severity ?? "Unknown")
            .OrderByDescending(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var severityGroup in findingsBySeverity)
        {
            var severity = severityGroup.Key;
            var findings = severityGroup.Value;
            var count = findings.Count;

            if (useColor)
            {
                Console.ForegroundColor = GetSeverityColor(severity);
            }

            output.WriteLine($"{severity}: {count} finding{(count == 1 ? "" : "s")}");

            if (useColor)
            {
                Console.ResetColor();
            }

            if (Verbose)
            {
                foreach (var finding in findings.OrderBy(f => f.FilePath).ThenBy(f => f.LineNumber))
                {
                    output.WriteLine($"  {finding.FilePath}:{finding.LineNumber} - {finding.Rule}");
                    if (!string.IsNullOrEmpty(finding.Secret) && finding.Secret.Length > 50)
                    {
                        output.WriteLine($"    Secret: {finding.Secret[..47]}...");
                    }
                    else if (!string.IsNullOrEmpty(finding.Secret))
                    {
                        output.WriteLine($"    Secret: {finding.Secret}");
                    }
                }
            }
        }
    }

    private static ConsoleColor GetSeverityColor(string severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "high" => ConsoleColor.Red,
            "critical" or "criticalerror" => ConsoleColor.DarkRed,
            "medium" => ConsoleColor.Yellow,
            "low" or "info" => ConsoleColor.Cyan,
            _ => ConsoleColor.White
        };
    }
}
