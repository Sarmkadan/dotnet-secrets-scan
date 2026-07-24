using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace DotnetSecretsScan;

/// <summary>
/// Generates an HTML report for a collection of secret findings.
/// </summary>
public sealed class HtmlReportWriter : IReportWriter
{
    /// <summary>
    /// Gets the format identifier for this writer: "html".
    /// </summary>
    public string FormatName => "html";

    /// <summary>
    /// Renders the scan result as an HTML document and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        output.Write(Generate(result.Findings));
    }

    /// <summary>
    /// Generates a complete HTML document containing a table of findings and a summary per rule.
    /// </summary>
    /// <param name="findings">The secret findings to include in the report.</param>
    /// <param name="title">The title of the report. Defaults to "Secrets Scan Report".</param>
    /// <returns>A string containing the full HTML document.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="findings"/> is null.</exception>
    public string Generate(IReadOnlyList<SecretFinding> findings, string title = "Secrets Scan Report")
    {
        ArgumentNullException.ThrowIfNull(findings);

        var sb = new StringBuilder();

        // Basic HTML skeleton
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine(" <meta charset=\"UTF-8\">");
        sb.AppendLine(" <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($" <title>{WebUtility.HtmlEncode(title)}</title>");
        sb.AppendLine(" <style>");
        sb.AppendLine(" body { font-family: Arial, Helvetica, sans-serif; margin: 20px; }");
        sb.AppendLine(" h1 { color: #2c3e50; }");
        sb.AppendLine(" table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }");
        sb.AppendLine(" th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
        sb.AppendLine(" th { background-color: #f2f2f2; }");
        sb.AppendLine(" tr:nth-child(even) { background-color: #fafafa; }");
        sb.AppendLine(" .summary-table { max-width: 400px; }");
        sb.AppendLine(" .severity-badge { display: inline-block; padding: 4px 12px; margin: 4px; border-radius: 4px; font-weight: bold; }");
        sb.AppendLine(" .severity-critical { background-color: #e74c3c; color: white; }");
        sb.AppendLine(" .severity-high { background-color: #e74c3c; color: white; }");
        sb.AppendLine(" .severity-medium { background-color: #f39c12; color: white; }");
        sb.AppendLine(" .severity-low { background-color: #3498db; color: white; }");
        sb.AppendLine(" .severity-info { background-color: #2ecc71; color: white; }");
        sb.AppendLine(" .filter-buttons { margin: 20px 0; }");
        sb.AppendLine(" .filter-btn { padding: 8px 16px; margin-right: 8px; cursor: pointer; border: 2px solid #ddd; background-color: white; }");
        sb.AppendLine(" .filter-btn.active { border-color: #333; font-weight: bold; }");
        sb.AppendLine(" </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine($" <h1>{WebUtility.HtmlEncode(title)}</h1>");

        // Severity summary badges
        sb.AppendLine(" <div class=\"severity-summary\">");
        sb.AppendLine(" <h2>Severity Summary</h2>");

        var criticalCount = findings.Count(f => string.Equals(f.Severity, "Critical", StringComparison.OrdinalIgnoreCase));
        var highCount = findings.Count(f => string.Equals(f.Severity, "High", StringComparison.OrdinalIgnoreCase));
        var mediumCount = findings.Count(f => string.Equals(f.Severity, "Medium", StringComparison.OrdinalIgnoreCase));
        var lowCount = findings.Count(f => string.Equals(f.Severity, "Low", StringComparison.OrdinalIgnoreCase));
        var infoCount = findings.Count(f => string.Equals(f.Severity, "Info", StringComparison.OrdinalIgnoreCase));

        if (criticalCount > 0)
            sb.AppendLine($" <span class=\"severity-badge severity-critical\">Critical: {criticalCount}</span>");
        if (highCount > 0)
            sb.AppendLine($" <span class=\"severity-badge severity-high\">High: {highCount}</span>");
        if (mediumCount > 0)
            sb.AppendLine($" <span class=\"severity-badge severity-medium\">Medium: {mediumCount}</span>");
        if (lowCount > 0)
            sb.AppendLine($" <span class=\"severity-badge severity-low\">Low: {lowCount}</span>");
        if (infoCount > 0)
            sb.AppendLine($" <span class=\"severity-badge severity-info\">Info: {infoCount}</span>");

        sb.AppendLine(" </div>");

        // Filter buttons
        sb.AppendLine(" <div class=\"filter-buttons\">");
        sb.AppendLine(" <button class=\"filter-btn active\" onclick=\"filterFindings('all')\">Show All</button>");
        sb.AppendLine(" <button class=\"filter-btn\" onclick=\"filterFindings('critical')\">Critical Only</button>");
        sb.AppendLine(" <button class=\"filter-btn\" onclick=\"filterFindings('high')\">High Only</button>");
        sb.AppendLine(" <button class=\"filter-btn\" onclick=\"filterFindings('medium')\">Medium Only</button>");
        sb.AppendLine(" <button class=\"filter-btn\" onclick=\"filterFindings('low')\">Low Only</button>");
        sb.AppendLine(" <button class=\"filter-btn\" onclick=\"filterFindings('info')\">Info Only</button>");
        sb.AppendLine(" </div>");

        // Summary section
        sb.AppendLine(" <h2>Summary by Rule</h2>");
        sb.AppendLine(" <table class=\"summary-table\">");
        sb.AppendLine(" <thead><tr><th>Rule</th><th>Findings</th></tr></thead>");
        sb.AppendLine(" <tbody>");

        var summary = findings
            .GroupBy(f => f.Rule)
            .OrderBy(g => g.Key);

        foreach (var group in summary)
        {
            sb.AppendLine(" <tr>");
            sb.AppendLine($" <td>{WebUtility.HtmlEncode(group.Key)}</td>");
            sb.AppendLine($" <td>{group.Count()}</td>");
            sb.AppendLine(" </tr>");
        }

        sb.AppendLine(" </tbody>");
        sb.AppendLine(" </table>");

        // Detailed findings table
        sb.AppendLine(" <h2>Findings</h2>");
        sb.AppendLine(" <table id=\"findings-table\">");
        sb.AppendLine(" <thead>");
        sb.AppendLine(" <tr>");
        sb.AppendLine(" <th>File</th>");
        sb.AppendLine(" <th>Line</th>");
        sb.AppendLine(" <th>Rule</th>");
        sb.AppendLine(" <th>Severity</th>");
        sb.AppendLine(" <th>Secret</th>");
        sb.AppendLine(" <th>Verified</th>");
        sb.AppendLine(" </tr>");
        sb.AppendLine(" </thead>");
        sb.AppendLine(" <tbody>");

        foreach (var f in findings)
        {
            var severityClass = GetSeverityClass(f.Severity);
            sb.AppendLine(" <tr class=\"severity-row\" data-severity=\"" + severityClass + "\">");
            sb.AppendLine($" <td>{WebUtility.HtmlEncode(f.FilePath)}</td>");
            sb.AppendLine($" <td>{f.LineNumber}</td>");
            sb.AppendLine($" <td>{WebUtility.HtmlEncode(f.Rule)}</td>");
            sb.AppendLine($" <td><span class=\"severity-badge {severityClass}\">{WebUtility.HtmlEncode(f.Severity)}</span></td>");
            sb.AppendLine($" <td>{WebUtility.HtmlEncode(MaskSecret(f.Secret))}</td>");
            sb.AppendLine($" <td>{WebUtility.HtmlEncode(f.Verified ?? "Not checked")}</td>");
            sb.AppendLine(" </tr>");
        }

        sb.AppendLine(" </tbody>");
        sb.AppendLine(" </table>");

        // Client-side filtering JavaScript
        sb.AppendLine(" <script>");
        sb.AppendLine(" function filterFindings(severity) {");
        sb.AppendLine("   const buttons = document.querySelectorAll('.filter-btn');");
        sb.AppendLine("   buttons.forEach(btn => btn.classList.remove('active')));");
        sb.AppendLine("   event.target.classList.add('active');");
        sb.AppendLine("   ");
        sb.AppendLine("   const rows = document.querySelectorAll('.severity-row');");
        sb.AppendLine("   rows.forEach(row => {");
        sb.AppendLine("     if (severity === 'all') {");
        sb.AppendLine("       row.style.display = '';");
        sb.AppendLine("     } else {");
        sb.AppendLine("       row.style.display = row.dataset.severity === severity ? '' : 'none';");
        sb.AppendLine("     }");
        sb.AppendLine("   });");
        sb.AppendLine(" }");
        sb.AppendLine(" </script>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    /// <summary>
    /// Writes the generated HTML report to the specified file path.
    /// </summary>
    /// <param name="findings">The secret findings to include in the report.</param>
    /// <param name="path">The file system path where the HTML file will be saved.</param>
    public void WriteToFile(IReadOnlyList<SecretFinding> findings, string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var html = Generate(findings);
        File.WriteAllText(path, html, Encoding.UTF8);
    }

    /// <summary>
    /// Masks a secret value, leaving the first four characters visible and replacing the rest with asterisks.
    /// </summary>
    /// <param name="secret">The secret string to mask.</param>
    /// <returns>The masked secret.</returns>
    public static string MaskSecret(string secret)
    {
        if (secret is null)
            throw new ArgumentNullException(nameof(secret));

        if (secret.Length <= 4)
            return secret;

        var visible = secret.Substring(0, 4);
        var masked = new string('*', secret.Length - 4);
        return visible + masked;
    }

    /// <summary>
    /// Gets the CSS class name for a severity level.
    /// </summary>
    /// <param name="severity">The severity level.</param>
    /// <returns>The CSS class name.</returns>
    private static string GetSeverityClass(string severity)
    {
        if (string.IsNullOrEmpty(severity))
            return string.Empty;

        var lowerSeverity = severity.Trim().ToLowerInvariant();

        return lowerSeverity switch
        {
            "critical" => "severity-critical",
            "high" => "severity-high",
            "medium" => "severity-medium",
            "low" => "severity-low",
            "info" => "severity-info",
            _ => "severity-medium"
        };
    }
}