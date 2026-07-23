using System;
using System.Collections.Generic;
using System.IO;
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
/// Writes scan results in JSON format.
/// </summary>
public sealed class JsonReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Gets the format identifier for this writer: "json".
    /// </summary>
    public string FormatName => "json";

    /// <summary>
    /// Renders the scan result as JSON and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        output.Write(ToJson(result));
    }

    /// <summary>
    /// Converts a scan result to JSON format.
    /// </summary>
    /// <param name="result">The scan result to serialize.</param>
    /// <returns>JSON representation of the scan result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToJson(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return JsonSerializer.Serialize(result, JsonOptions);
    }
}

/// <summary>
/// Provides thin, backward-compatible static entry points to the individual
/// <see cref="IReportWriter"/> implementations for the various output formats.
/// </summary>
public static class ReportWriter
{
    /// <summary>
    /// Writes scan results to the console with color-coded output by severity.
    /// </summary>
    /// <param name="result">The scan result to write.</param>
    /// <param name="verbose">Whether to include additional details in the output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static void WriteConsole(ScanResult result, bool verbose = false)
    {
        ArgumentNullException.ThrowIfNull(result);

        new ConsoleReportWriter(verbose).Write(result, Console.Out);
    }

    /// <summary>
    /// Converts a scan result to JSON format.
    /// </summary>
    /// <param name="result">The scan result to serialize.</param>
    /// <returns>JSON representation of the scan result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToJson(ScanResult result) => JsonReportWriter.ToJson(result);

    /// <summary>
    /// Converts a scan result to SARIF 2.1.0 format for CI integration.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>SARIF 2.1.0 JSON representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToSarif(ScanResult result) => SarifReportWriter.ToSarif(result);

    /// <summary>
    /// Converts a scan result to CSV format.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>CSV representation of the findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToCsv(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return CsvReportWriter.ToCsv(result.Findings);
    }

    /// <summary>
    /// Converts a scan result to JUnit XML format for CI integration.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>JUnit XML representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToJUnit(ScanResult result) => JUnitReportWriter.ToJUnit(result);
}
