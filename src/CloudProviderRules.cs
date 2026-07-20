using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

public static class CloudProviderRules
{
    public static IReadOnlyList<SecretRule> All { get; } = new List<SecretRule>
    {
        // ... existing rules ...

        new SecretRule(
            "SqlServerConnectionString",
            "SQL Server Connection String with Inline Password",
            @"Server=[^;]+;Data Source=[^;]+;Password=[^;]+",
            "Detects SQL Server connection strings with inline password",
            SecretSeverity.High),

        new SecretRule(
            "MongoDbUri",
            "MongoDB URI with Credentials",
            @"mongodb(?:\+srv)?://[^:]+:[^@]+@",
            "Detects MongoDB URIs with credentials",
            SecretSeverity.High),

        // ... existing rules ...
    };
}
