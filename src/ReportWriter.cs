using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DotnetSecretsScan;

/// <summary>
/// Represents the result of a secret scan operation.
/// </summary>
public sealed class ScanResult
{
    /// <summary>
    /// Gets or sets the collection of secret findings from the scan.
    /// </summary>
    public required IReadOnlyList<SecretFinding> Findings { get; set; }

    /// <summary>
    /// Gets or sets the total number of files scanned.
    /// </summary>
    public int TotalFilesScanned { get; set; }

    /// <summary>
    /// Gets or sets the total number of lines scanned.
    /// </summary>
    public long TotalLinesScanned { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the scan was performed.
    /// </summary>
    public DateTimeOffset ScanTimestamp { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Gets the count of findings by severity level.
    /// </summary>
    public Dictionary<string, int> FindingsBySeverity
    {
        get
        {
            var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var finding in Findings)
            {
                if (dict.TryGetValue(finding.Severity, out int count))
                {
                    dict[finding.Severity] = count + 1;
                }
                else
                {
                    dict[finding.Severity] = 1;
                }
            }

            return dict;
        }
    }

    /// <summary>
    /// Gets the total number of findings.
    /// </summary>
    public int TotalFindings => Findings.Count;
}

/// <summary>
/// Provides methods to write scan results in various formats.
/// </summary>
public static class ReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Writes scan results to the console with color-coded output by severity.
    /// </summary>
    /// <param name="result">The scan result to write.</param>
    /// <param name="verbose">Whether to include additional details in the output.</param>
    public static void WriteConsole(ScanResult result, bool verbose = false)
    {
        if (result is null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        Console.WriteLine($"Scan completed: {result.TotalFilesScanned} files, {result.TotalLinesScanned} lines, {result.TotalFindings} findings");
        Console.WriteLine($"Timestamp: {result.ScanTimestamp:yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine();

        if (result.TotalFindings == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ No secrets found");
            Console.ResetColor();
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
            var color = GetSeverityColor(severity);

            Console.ForegroundColor = color;
            Console.WriteLine($"{severity}: {count} finding{(count == 1 ? "" : "s")}");
            Console.ResetColor();

            if (verbose)
            {
                foreach (var finding in findings.OrderBy(f => f.FilePath).ThenBy(f => f.LineNumber))
                {
                    Console.WriteLine($"  {finding.FilePath}:{finding.LineNumber} - {finding.Rule}");
                    if (!string.IsNullOrEmpty(finding.Secret) && finding.Secret.Length > 50)
                    {
                        Console.WriteLine($"    Secret: {finding.Secret[..47]}...");
                    }
                    else if (!string.IsNullOrEmpty(finding.Secret))
                    {
                        Console.WriteLine($"    Secret: {finding.Secret}");
                    }
                }
            }
        }
    }

    /// <summary>
    /// Converts a scan result to JSON format.
    /// </summary>
    /// <param name="result">The scan result to serialize.</param>
    /// <returns>JSON representation of the scan result.</returns>
    public static string ToJson(ScanResult result)
    {
        if (result is null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        return JsonSerializer.Serialize(result, JsonOptions);
    }

    /// <summary>
    /// Converts a scan result to SARIF 2.1.0 format for CI integration.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>SARIF 2.1.0 JSON representation.</returns>
    public static string ToSarif(ScanResult result)
    {
        if (result is null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        var sarif = new
        {
            version = "2.1.0",
            schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "DotnetSecretsScan",
                            informationUri = "https://github.com/sarmkadan/dotnet-secrets-scan",
                            version = "0.1.0",
                            rules = new object[] { }
                        }
                    },
                    results = result.Findings
                        .Select(f => new
                        {
                            ruleId = f.Rule,
                            level = MapSeverityToSarifLevel(f.Severity),
                            message = new { text = $"Secret detected in {f.FilePath}:{f.LineNumber}" },
                            locations = new[]
                            {
                                new
                                {
                                    physicalLocation = new
                                    {
                                        artifactLocation = new { uri = f.FilePath },
                                        region = new
                                        {
                                            startLine = f.LineNumber,
                                            startColumn = 1
                                        }
                                    }
                                }
                            },
                            properties = new
                            {
                                severity = f.Severity,
                                secretValue = f.Secret
                            }
                        })
                        .ToArray(),
                    columnKind = "utf16CodeUnits"
                }
            }
        };

        return JsonSerializer.Serialize(sarif, JsonOptions);
    }

    /// <summary>
    /// Converts a scan result to CSV format.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>CSV representation of the findings.</returns>
    public static string ToCsv(ScanResult result)
    {
        if (result is null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        return CsvReportWriter.ToCsv(result.Findings);
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

    private static string MapSeverityToSarifLevel(string severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "high" or "critical" or "criticalerror" => "error",
            "medium" => "warning",
            "low" or "info" => "note",
            _ => "warning"
        };
    }
}
