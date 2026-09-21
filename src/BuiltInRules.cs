using System;
using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Provides a collection of built-in secret detection rules for common cloud providers, tokens, and credentials.
/// </summary>
/// <remarks>
/// <para>This collection includes rules for:</para>
/// <list type="bullet">
///     <item><description>AWS Access Keys and Secret Keys (SS001, SS002)</description></item>
///     <item><description>Private Keys in PEM/SSH formats (SS003)</description></item>
///     <item><description>Database Connection Strings with passwords (SS004)</description></item>
///     <item><description>Bearer Tokens and JWTs (SS005, JWT001)</description></item>
///     <item><description>GitHub PATs, OAuth Tokens, and Fine-Grained PATs (SS006, SS007, SS019)</description></item>
///     <item><description>Slack Tokens (SS008)</description></item>
///     <item><description>Generic API Keys, Secrets, and Private Keys (SS009, SS010, SS011)</description></item>
///     <item><description>Telegram Bot Tokens (SS012)</description></item>
///     <item><description>Stripe Live Keys (SS013, SS014)</description></item>
///     <item><description>Google API Keys (SS015)</description></item>
///     <item><description>Basic Auth Credentials (SS016)</description></item>
///     <item><description>NPM and NuGet API Keys (SS017, SS018)</description></item>
/// </list>
/// <para>
/// <b>False-Positive Caveats:</b> Generic patterns (SS009-SS011) and connection strings frequently match in documentation, sample code, or environment variable templates. Always verify matches in context before taking action.
/// </para>
/// </remarks>
public static class BuiltInRules
{
    /// <summary>
    /// Gets the complete list of built-in secret detection rules.
    /// </summary>
    /// <value>An immutable array of <see cref="SecretRule"/> instances.</value>
    public static ImmutableArray<SecretRule> All { get; } = new[]
    {
        // AWS Access Keys
        CreateRule(
            id: "SS001",
            name: "AWS Access Key ID",
            pattern: @"AKIA[0-9A-Z]{16}",
            description: "AWS Access Key ID (starts with AKIA followed by 16 alphanumeric characters)",
            severity: SecretSeverity.High
        ),

        // AWS Secret Access Key
        CreateRule(
            id: "SS002",
            name: "AWS Secret Access Key",
            pattern: @"aws(.{0,20})?(?i)(secret|private)(.{0,20})?[0-9a-z/+=]{40}",
            description: "AWS Secret Access Key (40-character alphanumeric string)",
            severity: SecretSeverity.High
        ),

        // Private keys (RSA, DSA, EC, OpenSSH)
        CreateRule(
            id: "SS003",
            name: "Private Key",
            pattern: @"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|SSH|PUBLIC|PRIVATE|ENCRYPTED) (.+?)-----",
            description: "Private key in PEM format (RSA, DSA, EC, OpenSSH, PGP)",
            severity: SecretSeverity.High
        ),

        // Connection strings with Password
        CreateRule(
            id: "SS004",
            name: "Connection String with Password",
            pattern: @"(?:Server|Data Source|Host|Database|Addr|Address)=[^;]+;.*?(?:Password|pwd|PWD)=[^;]+",
            description: "Database connection string containing password parameter",
            severity: SecretSeverity.High
        ),

        // Bearer tokens and JWT
        CreateRule(
            id: "SS005",
            name: "Bearer Token/JWT",
            pattern: @"Bearer [a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]*",
            description: "Bearer token or JWT (header.payload.signature format)",
            severity: SecretSeverity.High
        ),

        // JWT
        CreateRule(
            id: "JWT001",
            name: "JSON Web Token",
            pattern: @"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            description: "JSON Web Token (JWT) (starts with eyJ followed by three base64url segments separated by dots)",
            severity: SecretSeverity.High
        ),

        // GitHub Personal Access Token
        CreateRule(
            id: "SS006",
            name: "GitHub Personal Access Token",
            pattern: @"ghp_[a-zA-Z0-9]{36}",
            description: "GitHub Personal Access Token (ghp_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // GitHub OAuth Token
        CreateRule(
            id: "SS007",
            name: "GitHub OAuth Token",
            pattern: @"gho_[a-zA-Z0-9]{36}",
            description: "GitHub OAuth Token (gho_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // Slack tokens
        CreateRule(
            id: "SS008",
            name: "Slack Token",
            pattern: @"xox[baprs]-[a-zA-Z0-9-]+",
            description: "Slack token (xoxb, xoxp, xoxa, xoxr, xoxs)",
            severity: SecretSeverity.High
        ),

        // Generic API key
        CreateRule(
            id: "SS009",
            name: "Generic API Key",
            pattern: @"api[_-]?key[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic API key pattern (32+ characters)",
            severity: SecretSeverity.Medium
        ),

        // Generic secret
        CreateRule(
            id: "SS010",
            name: "Generic Secret",
            pattern: @"secret[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic secret key pattern (32+ characters)",
            severity: SecretSeverity.Medium
        ),

        // Generic private key
        CreateRule(
            id: "SS011",
            name: "Generic Private Key",
            pattern: @"private[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic private key pattern (32+ characters)",
            severity: SecretSeverity.High
        ),

        // Telegram Bot Token
        CreateRule(
            id: "SS012",
            name: "Telegram Bot Token",
            pattern: @"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",
            description: "Telegram Bot Token (9-10 digit ID followed by colon and 35 character token)",
            severity: SecretSeverity.High
        ),

        // Stripe API Key
        CreateRule(
            id: "SS013",
            name: "Stripe API Key",
            pattern: @"sk_live_[0-9a-zA-Z]{24}",
            description: "Stripe live secret key (sk_live_ prefix followed by 24 characters)",
            severity: SecretSeverity.High
        ),

        // Stripe Publishable Key
        CreateRule(
            id: "SS014",
            name: "Stripe Publishable Key",
            pattern: @"pk_live_[0-9a-zA-Z]{24}",
            description: "Stripe live publishable key (pk_live_ prefix followed by 24 characters)",
            severity: SecretSeverity.Medium
        ),

        // Google API Key
        CreateRule(
            id: "SS015",
            name: "Google API Key",
            pattern: @"AIza[0-9A-Za-z\-_]{35}",
            description: "Google API Key (AIza prefix followed by 35 characters)",
            severity: SecretSeverity.Medium
        ),

        // Basic Auth credentials
        CreateRule(
            id: "SS016",
            name: "Basic Auth Credentials",
            pattern: @"(?:Authorization|Proxy-Authorization): Basic [a-zA-Z0-9\+/=]{10,}",
            description: "Base64 encoded Basic Authentication credentials",
            severity: SecretSeverity.High
        ),

        // NPM token
        CreateRule(
            id: "SS017",
            name: "NPM Token",
            pattern: @"npm_[a-zA-Z0-9]{36}",
            description: "NPM authentication token (npm_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // NuGet API Key
        CreateRule(
            id: "SS018",
            name: "NuGet API Key",
            pattern: @"oy2[a-zA-Z0-9]{32}",
            description: "NuGet API key (oy2 prefix followed by 32 characters)",
            severity: SecretSeverity.High
        ),

        // GitHub Fine-Grained Personal Access Token
        CreateRule(
            id: "SS019",
            name: "GitHub Fine-Grained PAT",
            pattern: @"github_pat_[A-Za-z0-9_]{40}",
            description: "GitHub fine-grained personal access token (github_pat_ prefix followed by 40 characters)",
            severity: SecretSeverity.High
        )
    }.ToImmutableArray();

    /// <summary>
    /// Creates a new <see cref="SecretRule"/> instance.
    /// </summary>
    /// <param name="id">The rule identifier.</param>
    /// <param name="name">The human-readable name.</param>
    /// <param name="pattern">The regex pattern.</param>
    /// <param name="description">The description.</param>
    /// <param name="severity">The severity level.</param>
    /// <returns>A configured <see cref="SecretRule"/> instance.</returns>
    private static SecretRule CreateRule(
        string id,
        string name,
        string pattern,
        string description,
        SecretSeverity severity) =>
        new(id, name, pattern, description, severity);
}
