using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DotnetSecretsScan;

/// <summary>
/// Writes scan results in CSV format.
/// </summary>
public sealed class CsvReportWriter : IReportWriter
{
    /// <summary>
    /// Gets the format identifier for this writer: "csv".
    /// </summary>
    public string FormatName => "csv";

    /// <summary>
    /// Renders the scan result as CSV and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        output.Write(ToCsv(result.Findings));
    }

    /// <summary>
    /// Converts a collection of secret findings to CSV format.
    /// </summary>
    /// <param name="findings">The secret findings to convert.</param>
    /// <returns>CSV representation of the findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="findings"/> is null.</exception>
    public static string ToCsv(IEnumerable<SecretFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var sb = new StringBuilder();

        // CSV header
        sb.AppendLine("Rule,File,Line,Severity,Secret");

        // CSV data rows
        foreach (var finding in findings.OrderBy(f => f.FilePath).ThenBy(f => f.LineNumber))
        {
            var rule = EscapeCsvField(finding.Rule);
            var file = EscapeCsvField(finding.FilePath);
            var line = finding.LineNumber.ToString();
            var severity = EscapeCsvField(finding.Severity);
            var secret = RedactSecret(finding.Secret);
            var redactedSecret = EscapeCsvField(secret);

            sb.AppendLine($"{rule},{file},{line},{severity},{redactedSecret}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Writes a collection of secret findings to a CSV file.
    /// </summary>
    /// <param name="findings">The secret findings to write.</param>
    /// <param name="filePath">The file path where the CSV will be saved.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="filePath"/> is null.</exception>
    public static void WriteToFile(IEnumerable<SecretFinding> findings, string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        var csv = ToCsv(findings);
        File.WriteAllText(filePath, csv, Encoding.UTF8);
    }

    /// <summary>
    /// Escapes a field for CSV format by wrapping it in quotes if it contains special characters.
    /// </summary>
    /// <param name="field">The field to escape.</param>
    /// <returns>The escaped CSV field.</returns>
    private static string EscapeCsvField(string field)
    {
        if (field is null)
        {
            return string.Empty;
        }

        // Check if field contains comma, quote, or newline
        if (field.Contains(',', StringComparison.Ordinal) ||
            field.Contains('"', StringComparison.Ordinal) ||
            field.Contains('\n', StringComparison.Ordinal) ||
            field.Contains('\r', StringComparison.Ordinal))
        {
            // Escape quotes by doubling them and wrap in quotes
            return '"' + field.Replace("\"", "\"\"") + '"';
        }

        return field;
    }

    /// <summary>
    /// Redacts a secret value, showing only the last 4 characters.
    /// </summary>
    /// <param name="secret">The secret to redact.</param>
    /// <returns>The redacted secret.</returns>
    private static string RedactSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return string.Empty;
        }

        if (secret.Length <= 4)
        {
            return "****";
        }

        return $"****{secret.Substring(secret.Length - 4)}";
    }
}
