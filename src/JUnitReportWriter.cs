using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace DotnetSecretsScan;

/// <summary>
/// Writes scan results in JUnit XML format.
/// This format is commonly used by CI/CD systems to consume test failures.
/// </summary>
public sealed class JUnitReportWriter : IReportWriter
{
    /// <summary>
    /// Gets the format identifier for this writer: "junit".
    /// </summary>
    public string FormatName => "junit";

    /// <summary>
    /// Renders the scan result as JUnit XML and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        output.Write(ToJUnit(result));
    }

    /// <summary>
    /// Converts a collection of secret findings to JUnit XML format.
    /// </summary>
    /// <param name="findings">The secret findings to convert.</param>
    /// <param name="scanTimestamp">The timestamp when the scan was performed.</param>
    /// <returns>JUnit XML representation of the findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="findings"/> is null.</exception>
    public static string ToJUnit(IEnumerable<SecretFinding> findings, DateTimeOffset scanTimestamp)
    {
        ArgumentNullException.ThrowIfNull(findings);

        // Group findings by file path for testsuite organization
        var findingsByFile = findings
            .GroupBy(f => f.FilePath)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .ToList();

        var junitDoc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement("testsuites",
                new XAttribute("name", "dotnet-secrets-scan"),
                new XAttribute("time", "0"),
                new XAttribute("tests", findingsByFile.Sum(g => g.Count()).ToString()),
                new XAttribute("failures", findingsByFile.Sum(g => g.Count()).ToString()),
                new XAttribute("timestamp", scanTimestamp.ToString("yyyy-MM-ddTHH:mm:sszzz"))
            )
        );

        var testSuitesElement = junitDoc.Root;

        if (testSuitesElement is null)
        {
            throw new InvalidOperationException("Failed to create JUnit XML document");
        }

        foreach (var fileGroup in findingsByFile)
        {
            var filePath = fileGroup.Key;
            var fileFindings = fileGroup.ToList();

            // Create testsuite for each file
            var testSuiteElement = new XElement("testsuite",
                new XAttribute("name", filePath),
                new XAttribute("tests", fileFindings.Count.ToString()),
                new XAttribute("failures", fileFindings.Count.ToString()),
                new XAttribute("time", "0"),
                new XAttribute("timestamp", scanTimestamp.ToString("yyyy-MM-ddTHH:mm:sszzz"))
            );

            // Create testcase for each finding
            foreach (var finding in fileFindings.OrderBy(f => f.LineNumber))
            {
                var testCaseElement = new XElement("testcase",
                    new XAttribute("name", $"Secret detection: {finding.Rule} at line {finding.LineNumber}"),
                    new XAttribute("classname", System.IO.Path.GetFileNameWithoutExtension(filePath)),
                    new XAttribute("file", filePath),
                    new XAttribute("line", finding.LineNumber.ToString()),
                    new XAttribute("time", "0")
                );

                // Add failure element with details
                var failureMessage = $"Secret detected in {filePath}:{finding.LineNumber}\nRule: {finding.Rule}\nSeverity: {finding.Severity}\nSecret: {RedactSecret(finding.Secret)}";

                testCaseElement.Add(new XElement("failure",
                    new XAttribute("message", failureMessage),
                    new XAttribute("type", "SecretDetection")
                ));

                testSuiteElement.Add(testCaseElement);
            }

            testSuitesElement.Add(testSuiteElement);
        }

        return junitDoc.ToString();
    }

    /// <summary>
    /// Writes a collection of secret findings to a JUnit XML file.
    /// </summary>
    /// <param name="findings">The secret findings to write.</param>
    /// <param name="filePath">The file path where the JUnit XML will be saved.</param>
    /// <param name="scanTimestamp">The timestamp when the scan was performed.</param>
    public static void WriteToFile(IEnumerable<SecretFinding> findings, string filePath, DateTimeOffset scanTimestamp)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        var junitXml = ToJUnit(findings, scanTimestamp);
        System.IO.File.WriteAllText(filePath, junitXml);
    }

    /// <summary>
    /// Converts a scan result to JUnit XML format.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>JUnit XML representation of the findings.</returns>
    public static string ToJUnit(ScanResult result)
    {
        if (result is null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        return ToJUnit(result.Findings, result.ScanTimestamp);
    }

    /// <summary>
    /// Writes a scan result to a JUnit XML file.
    /// </summary>
    /// <param name="result">The scan result to write.</param>
    /// <param name="filePath">The file path where the JUnit XML will be saved.</param>
    public static void WriteToFile(ScanResult result, string filePath)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        WriteToFile(result.Findings, filePath, result.ScanTimestamp);
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