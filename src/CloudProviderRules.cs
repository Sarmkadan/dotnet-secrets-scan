using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

public static class CloudProviderRules
{
    public static IReadOnlyList<SecretRule> All { get; } = new List<SecretRule>
    {
        // ... existing rules ...

        CreateRule(
            "SqlServerConnectionString",
            "SQL Server Connection String with Inline Password",
            @"Server=[^;]+;Data Source=[^;]+;Password=[^;]+",
            "Detects SQL Server connection strings with inline password",
            SecretSeverity.High),

        CreateRule(
            "MongoDbUri",
            "MongoDB URI with Credentials",
            @"mongodb(?:\+srv)?://[^:]+:[^@]+@",
            "Detects MongoDB URIs with credentials",
            SecretSeverity.High),

        // ... existing rules ...
    };

    private static SecretRule CreateRule(
        string id,
        string name,
        string pattern,
        string description,
        SecretSeverity severity) =>
        new(id, name, pattern, description, severity);
}
