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
public sealed class HtmlReportWriter
{
    /// <summary>
    /// Generates a complete HTML document containing a table of findings and a summary per rule.
    /// </summary>
    /// <param name="findings">The secret findings to include in the report.</param>
    /// <param name="title">The title of the report. Defaults to "Secrets Scan Report".</param>
    /// <returns>A string containing the full HTML document.</returns>
    public string Generate(IReadOnlyList<SecretFinding> findings, string title = "Secrets Scan Report")
    {
        if (findings is null)
            throw new ArgumentNullException(nameof(findings));

        var sb = new StringBuilder();

        // Basic HTML skeleton
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("    <meta charset=\"UTF-8\">");
        sb.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"    <title>{WebUtility.HtmlEncode(title)}</title>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: Arial, Helvetica, sans-serif; margin: 20px; }");
        sb.AppendLine("        h1 { color: #2c3e50; }");
        sb.AppendLine("        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }");
        sb.AppendLine("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
        sb.AppendLine("        th { background-color: #f2f2f2; }");
        sb.AppendLine("        tr:nth-child(even) { background-color: #fafafa; }");
        sb.AppendLine("        .summary-table { max-width: 400px; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine($"    <h1>{WebUtility.HtmlEncode(title)}</h1>");

        // Summary section
        sb.AppendLine("    <h2>Summary by Rule</h2>");
        sb.AppendLine("    <table class=\"summary-table\">");
        sb.AppendLine("        <thead><tr><th>Rule</th><th>Findings</th></tr></thead>");
        sb.AppendLine("        <tbody>");

        var summary = findings
            .GroupBy(f => f.Rule)
            .OrderBy(g => g.Key);

        foreach (var group in summary)
        {
            sb.AppendLine("            <tr>");
            sb.AppendLine($"                <td>{WebUtility.HtmlEncode(group.Key)}</td>");
            sb.AppendLine($"                <td>{group.Count()}</td>");
            sb.AppendLine("            </tr>");
        }

        sb.AppendLine("        </tbody>");
        sb.AppendLine("    </table>");

        // Detailed findings table
        sb.AppendLine("    <h2>Findings</h2>");
        sb.AppendLine("    <table>");
        sb.AppendLine("        <thead>");
        sb.AppendLine("            <tr>");
        sb.AppendLine("                <th>File</th>");
        sb.AppendLine("                <th>Line</th>");
        sb.AppendLine("                <th>Rule</th>");
        sb.AppendLine("                <th>Secret</th>");
        sb.AppendLine("            </tr>");
        sb.AppendLine("        </thead>");
        sb.AppendLine("        <tbody>");

        foreach (var f in findings)
        {
            sb.AppendLine("            <tr>");
            sb.AppendLine($"                <td>{WebUtility.HtmlEncode(f.FilePath)}</td>");
            sb.AppendLine($"                <td>{f.LineNumber}</td>");
            sb.AppendLine($"                <td>{WebUtility.HtmlEncode(f.Rule)}</td>");
            sb.AppendLine($"                <td>{WebUtility.HtmlEncode(MaskSecret(f.Secret))}</td>");
            sb.AppendLine("            </tr>");
        }

        sb.AppendLine("        </tbody>");
        sb.AppendLine("    </table>");

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
        if (path is null)
            throw new ArgumentNullException(nameof(path));

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
}
