using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DotnetSecretsScan;

public static class SarifReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string ToSarif(IEnumerable<SecretFinding> findings)
    {
        if (findings is null)
        {
            throw new ArgumentNullException(nameof(findings));
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
