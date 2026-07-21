using System.Collections.Generic;

namespace DotnetSecretsScan;

/// <summary>
/// Severity level of a detected secret.
/// </summary>
public enum SecretSeverity
{
    /// <summary>
    /// Low severity - informational only
    /// </summary>
    Low,

    /// <summary>
    /// Medium severity - potential issue
    /// </summary>
    Medium,

    /// <summary>
    /// High severity - confirmed secret that should be rotated
    /// </summary>
    High
}

/// <summary>
/// Represents a secret detection rule.
/// </summary>
public class SecretRule
{
    /// <summary>
    /// Gets the rule identifier (e.g., SS001).
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets the human-readable name of the rule.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the regex pattern to match secrets.
    /// </summary>
    public string Pattern { get; }

    /// <summary>
    /// Gets the description of what this rule matches.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Gets the severity level of matches.
    /// </summary>
    public SecretSeverity Severity { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretRule"/> class.
    /// </summary>
    /// <param name="id">The rule identifier.</param>
    /// <param name="name">The human-readable name.</param>
    /// <param name="pattern">The regex pattern.</param>
    /// <param name="description">The description.</param>
    /// <param name="severity">The severity level.</param>
    public SecretRule(string id, string name, string pattern, string description, SecretSeverity severity)
    {
        Id = id;
        Name = name;
        Pattern = pattern;
        Description = description;
        Severity = severity;
    }
}

/// <summary>
/// Built-in secret detection rules for common secret patterns.
/// </summary>
public static class BuiltInRules
{
    /// <summary>
    /// Gets all built-in secret detection rules.
    /// </summary>
    public static IReadOnlyList<SecretRule> All = new List<SecretRule>
    {
        // AWS Access Keys
        new SecretRule(
            id: "SS001",
            name: "AWS Access Key ID",
            pattern: @"AKIA[0-9A-Z]{16}",
            description: "AWS Access Key ID (starts with AKIA followed by 16 alphanumeric characters)",
            severity: SecretSeverity.High
        ),

        // AWS Secret Access Key
        new SecretRule(
            id: "SS002",
            name: "AWS Secret Access Key",
            pattern: @"aws(.{0,20})?(?i)(secret|private)(.{0,20})?[0-9a-z/+=]{40}",
            description: "AWS Secret Access Key (40-character alphanumeric string)",
            severity: SecretSeverity.High
        ),

        // Private keys (RSA, DSA, EC, OpenSSH)
        new SecretRule(
            id: "SS003",
            name: "Private Key",
            pattern: @"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|SSH|PUBLIC|PRIVATE|ENCRYPTED) (.+?)-----",
            description: "Private key in PEM format (RSA, DSA, EC, OpenSSH, PGP)",
            severity: SecretSeverity.High
        ),

        // Connection strings with Password
        new SecretRule(
            id: "SS004",
            name: "Connection String with Password",
            pattern: @"(?:Server|Data Source|Host|Database|Addr|Address)=[^;]+;.*?(?:Password|pwd|PWD)=[^;]+",
            description: "Database connection string containing password parameter",
            severity: SecretSeverity.High
        ),

        // Bearer tokens and JWT
        new SecretRule(
            id: "SS005",
            name: "Bearer Token/JWT",
            pattern: @"Bearer [a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]*",
            description: "Bearer token or JWT (header.payload.signature format)",
            severity: SecretSeverity.High
        ),

        // JWT
        new SecretRule(
            id: "JWT001",
            name: "JSON Web Token",
            pattern: @"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            description: "JSON Web Token (JWT) (starts with eyJ followed by three base64url segments separated by dots)",
            severity: SecretSeverity.High
        ),

        // GitHub Personal Access Token
        new SecretRule(
            id: "SS006",
            name: "GitHub Personal Access Token",
            pattern: @"ghp_[a-zA-Z0-9]{36}",
            description: "GitHub Personal Access Token (ghp_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // GitHub OAuth Token
        new SecretRule(
            id: "SS007",
            name: "GitHub OAuth Token",
            pattern: @"gho_[a-zA-Z0-9]{36}",
            description: "GitHub OAuth Token (gho_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // Slack tokens
        new SecretRule(
            id: "SS008",
            name: "Slack Token",
            pattern: @"xox[baprs]-[a-zA-Z0-9-]+",
            description: "Slack token (xoxb, xoxp, xoxa, xoxr, xoxs)",
            severity: SecretSeverity.High
        ),

        // Generic API key
        new SecretRule(
            id: "SS009",
            name: "Generic API Key",
            pattern: @"api[_-]?key[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic API key pattern (32+ characters)",
            severity: SecretSeverity.Medium
        ),

        // Generic secret
        new SecretRule(
            id: "SS010",
            name: "Generic Secret",
            pattern: @"secret[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic secret key pattern (32+ characters)",
            severity: SecretSeverity.Medium
        ),

        // Generic private key
        new SecretRule(
            id: "SS011",
            name: "Generic Private Key",
            pattern: @"private[\s:=]{0,5}[\""]?[a-zA-Z0-9]{32,}[\""]?",
            description: "Generic private key pattern (32+ characters)",
            severity: SecretSeverity.High
        ),

        // Telegram Bot Token
        new SecretRule(
            id: "SS012",
            name: "Telegram Bot Token",
            pattern: @"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",
            description: "Telegram Bot Token (9-10 digit ID followed by colon and 35 character token)",
            severity: SecretSeverity.High
        ),

        // Stripe API Key
        new SecretRule(
            id: "SS013",
            name: "Stripe API Key",
            pattern: @"sk_live_[0-9a-zA-Z]{24}",
            description: "Stripe live secret key (sk_live_ prefix followed by 24 characters)",
            severity: SecretSeverity.High
        ),

        // Stripe Publishable Key
        new SecretRule(
            id: "SS014",
            name: "Stripe Publishable Key",
            pattern: @"pk_live_[0-9a-zA-Z]{24}",
            description: "Stripe live publishable key (pk_live_ prefix followed by 24 characters)",
            severity: SecretSeverity.Medium
        ),

        // Google API Key
        new SecretRule(
            id: "SS015",
            name: "Google API Key",
            pattern: @"AIza[0-9A-Za-z\-_]{35}",
            description: "Google API Key (AIza prefix followed by 35 characters)",
            severity: SecretSeverity.Medium
        ),

        // Basic Auth credentials
        new SecretRule(
            id: "SS016",
            name: "Basic Auth Credentials",
            pattern: @"(?:Authorization|Proxy-Authorization): Basic [a-zA-Z0-9\+/=]{10,}",
            description: "Base64 encoded Basic Authentication credentials",
            severity: SecretSeverity.High
        ),

        // NPM token
        new SecretRule(
            id: "SS017",
            name: "NPM Token",
            pattern: @"npm_[a-zA-Z0-9]{36}",
            description: "NPM authentication token (npm_ prefix followed by 36 characters)",
            severity: SecretSeverity.High
        ),

        // NuGet API Key
        new SecretRule(
            id: "SS018",
            name: "NuGet API Key",
            pattern: @"oy2[a-zA-Z0-9]{32}",
            description: "NuGet API key (oy2 prefix followed by 32 characters)",
            severity: SecretSeverity.High
        ),

        // GitHub Fine-Grained Personal Access Token
        new SecretRule(
            id: "SS019",
            name: "GitHub Fine-Grained PAT",
            pattern: @"github_pat_[A-Za-z0-9_]{40}",
            description: "GitHub fine-grained personal access token (github_pat_ prefix followed by 40 characters)",
            severity: SecretSeverity.High
        )
    };
}
