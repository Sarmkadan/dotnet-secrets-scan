using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DotnetSecretsScan;

/// <summary>
/// Writes scan results in SARIF 2.1.0 format for CI integration.
/// </summary>
public sealed class SarifReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Gets the format identifier for this writer: "sarif".
    /// </summary>
    public string FormatName => "sarif";

    /// <summary>
    /// Renders the scan result as SARIF 2.1.0 JSON and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="output"/> is null.</exception>
    public void Write(ScanResult result, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(output);

        output.Write(ToSarif(result.Findings));
    }

    /// <summary>
    /// Converts a collection of secret findings to SARIF 2.1.0 format.
    /// </summary>
    /// <param name="findings">The secret findings to convert.</param>
    /// <returns>SARIF 2.1.0 JSON representation of the findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="findings"/> is null.</exception>
    public static string ToSarif(IEnumerable<SecretFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

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
                            name = "dotnet-secrets-scan",
                            informationUri = "https://github.com/sarmkadan/dotnet-secrets-scan",
                            version = "0.1.0",
                            rules = new object[] { }
                        }
                    },
                    results = findings
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
                                secretValue = f.Secret,
                                verified = f.Verified
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
    /// Converts a scan result to SARIF 2.1.0 format.
    /// </summary>
    /// <param name="result">The scan result to convert.</param>
    /// <returns>SARIF 2.1.0 JSON representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is null.</exception>
    public static string ToSarif(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return ToSarif(result.Findings);
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
