using System;
using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Provides a collection of <see cref="SecretRule"/> instances for detecting secrets from major cloud providers.
/// <para>
/// Rules include:
/// <list type="bullet">
///   <item><description>AWS Access Key ID: Matches <c>AKIA</c> followed by 16 alphanumeric characters. Example: <c>AKIAIOSFODNN7EXAMPLE</c>.</description></item>
///   <item><description>AWS Secret Access Key: Matches 40-character base64-like string. Example: <c>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</c>.</description></item>
///   <item><description>Azure Storage Connection String: Matches <c>DefaultEndpointsProtocol=https;</c> followed by account and key details. Example: <c>DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...</c>.</description></item>
///   <item><description>Azure Service Principal Secret: Matches 34-character base64-like string. Example: <c>~1234567890abcdefghijklmnopqrstuvwxyz</c>.</description></item>
///   <item><description>GCP Service Account Key: Matches JSON object containing <c>"type": "service_account"</c>. Example: <c>{"type": "service_account", "project_id": "..."}</c>.</description></item>
///   <item><description>GCP API Key: Matches <c>AIza</c> followed by 35 alphanumeric characters. Example: <c>AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe</c>.</description></item>
/// </list>
/// </para>
/// </summary>
/// <seealso cref="SecretRule"/>
/// <seealso href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html">AWS IAM Access Keys</seealso>
/// <seealso href="https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal">Azure AD App Registration Secrets</seealso>
/// <seealso href="https://cloud.google.com/iam/docs/keys-create-delete">GCP IAM Service Account Keys</seealso>
public static class CloudProviderRules
{
    /// <summary>
    /// Gets the immutable collection of all cloud provider detection rules.
    /// </summary>
    public static ImmutableArray<SecretRule> All { get; } = new[]
    {
        // AWS Access Key ID
        CreateRule(
            "AwsAccessKeyId",
            "AWS Access Key ID",
            @"AKIA[0-9A-Z]{16}",
            "Detects AWS Access Key IDs, which start with AKIA followed by 16 uppercase alphanumeric characters. Example: AKIAIOSFODNN7EXAMPLE",
            SecretSeverity.High),

        // AWS Secret Access Key
        CreateRule(
            "AwsSecretAccessKey",
            "AWS Secret Access Key",
            @"[A-Za-z0-9/+=]{40}",
            "Detects AWS Secret Access Keys, typically 40 characters long. Example: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            SecretSeverity.High),

        // Azure Storage Connection String
        CreateRule(
            "AzureStorageConnectionString",
            "Azure Storage Connection String",
            @"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
            "Detects Azure Storage connection strings containing account names and keys. Example: DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=...",
            SecretSeverity.High),

        // Azure Service Principal Secret
        CreateRule(
            "AzureServicePrincipalSecret",
            "Azure Service Principal Secret",
            @"[A-Za-z0-9~._+/-]{34}",
            "Detects Azure AD App Registration secrets (client secrets), typically 34 characters. Example: ~1234567890abcdefghijklmnopqrstuvwxyz",
            SecretSeverity.High),

        // GCP Service Account Key
        CreateRule(
            "GcpServiceAccountKey",
            "GCP Service Account Key",
            @"""\s*""type""\s*:\s*""service_account""",
            "Detects Google Cloud Platform service account key JSON files. Example: {\"type\": \"service_account\", \"project_id\": \"...\"}",
            SecretSeverity.High),

        // GCP API Key
        CreateRule(
            "GcpApiKey",
            "GCP API Key",
            @"AIza[0-9A-Za-z_-]{35}",
            "Detects Google Cloud Platform API keys, which start with AIza followed by 35 characters. Example: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
            SecretSeverity.High),

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
    }.ToImmutableArray();

    /// <summary>
    /// Creates a new <see cref="SecretRule"/> for detecting a specific secret format.
    /// </summary>
    /// <param name="id">Unique identifier for the rule (e.g., SS019).</param>
    /// <param name="name">Display name of the rule.</param>
    /// <param name="pattern">Regular expression pattern to match the secret.</param>
    /// <param name="description">Human-readable description of what the rule detects, including token format and examples.</param>
    /// <param name="severity">The severity level assigned to findings from this rule.</param>
    /// <returns>A configured <see cref="SecretRule"/> instance.</returns>
    private static SecretRule CreateRule(
        string id,
        string name,
        string pattern,
        string description,
        SecretSeverity severity) =>
        new(id, name, pattern, description, severity);
}
