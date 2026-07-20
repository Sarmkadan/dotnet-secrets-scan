using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DotnetSecretsScan;

/// <summary>
/// Provides methods to write scan results in CSV format.
/// </summary>
public static class CsvReportWriter
{
    /// <summary>
    /// Converts a collection of secret findings to CSV format.
    /// </summary>
    /// <param name="findings">The secret findings to convert.</param>
    /// <returns>CSV representation of the findings.</returns>
    public static string ToCsv(IEnumerable<SecretFinding> findings)
    {
        if (findings is null)
        {
            throw new ArgumentNullException(nameof(findings));
        }

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
    public static void WriteToFile(IEnumerable<SecretFinding> findings, string filePath)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        var csv = ToCsv(findings);
        System.IO.File.WriteAllText(filePath, csv, Encoding.UTF8);
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