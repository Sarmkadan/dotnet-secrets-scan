using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Configuration settings for entropy-based secret detection.
/// Allows teams to tune detection thresholds based on their specific needs.
/// </summary>
/// <param name="Threshold">Minimum entropy threshold to consider as a potential secret.</param>
/// <param name="MinLength">Minimum length of string to consider for entropy analysis.</param>
/// <param name="ContextWindow">Number of characters to search around a match for assignment context keywords.</param>
/// <param name="HexEntropyThreshold">Higher entropy threshold for pure hex strings (GUIDs, hashes).</param>
/// <param name="Base64EntropyThreshold">Higher entropy threshold for Base64 strings.</param>
/// <param name="ContextKeywords">Keywords that indicate a secret assignment context.</param>
public sealed record EntropyDetectionSettings(
    double Threshold = 4.5,
    int MinLength = 20,
    int ContextWindow = 50,
    double HexEntropyThreshold = 5.0,
    double Base64EntropyThreshold = 4.0,
    string[] ContextKeywords = null!)
{
    /// <summary>
    /// Default settings optimized for reducing false positives while maintaining good detection.
    /// </summary>
    public static readonly EntropyDetectionSettings Default = new();

    /// <summary>
    /// Creates settings with custom thresholds.
    /// </summary>
    /// <param name="threshold">Minimum entropy threshold.</param>
    /// <param name="minLength">Minimum string length.</param>
    /// <param name="contextWindow">Context search window size.</param>
    /// <param name="hexEntropyThreshold">Hex string entropy threshold.</param>
    /// <param name="base64EntropyThreshold">Base64 string entropy threshold.</param>
    /// <param name="contextKeywords">Assignment context keywords.</param>
    /// <returns>Configured settings instance.</returns>
    public static EntropyDetectionSettings Create(
        double threshold = 4.5,
        int minLength = 20,
        int contextWindow = 50,
        double hexEntropyThreshold = 5.0,
        double base64EntropyThreshold = 4.0,
        string[]? contextKeywords = null)
    {
        return new EntropyDetectionSettings(
            Threshold: threshold,
            MinLength: minLength,
            ContextWindow: contextWindow,
            HexEntropyThreshold: hexEntropyThreshold,
            Base64EntropyThreshold: base64EntropyThreshold,
            ContextKeywords: contextKeywords ??
                ["key", "token", "secret", "password", "pwd", "api", "access", "credential"]);
    }
}

public static class EntropyDetector
{
    /// <summary>
    /// Calculates the Shannon entropy of a string.
    /// </summary>
    /// <param name="s">The input string.</param>
    /// <returns>The entropy value in bits.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="s"/> is null.</exception>
    public static double ShannonEntropy(string s)
    {
        ArgumentNullException.ThrowIfNull(s);

        if (string.IsNullOrEmpty(s))
        {
            return 0.0;
        }

        return ShannonEntropy(s.AsSpan());
    }

    /// <summary>
    /// Calculates the Shannon entropy of a character span.
    /// </summary>
    /// <param name="span">The input character span.</param>
    /// <returns>The entropy value in bits.</returns>
    public static double ShannonEntropy(ReadOnlySpan<char> span)
    {
        if (span.IsEmpty)
        {
            return 0.0;
        }

        // Count frequency of each character
        var frequency = new Dictionary<char, int>();
        foreach (char c in span)
        {
            if (frequency.TryGetValue(c, out int count))
            {
                frequency[c] = count + 1;
            }
            else
            {
                frequency[c] = 1;
            }
        }

        double entropy = 0.0;
        int length = span.Length;

        foreach (var pair in frequency)
        {
            double probability = (double)pair.Value / length;
            entropy -= probability * Math.Log(probability, 2);
        }

        return entropy;
    }

    /// <summary>
    /// Scans file lines for potential secrets based on entropy threshold.
    /// </summary>
    /// <param name="filePath">Path to the file being scanned.</param>
    /// <param name="lines">File content lines.</param>
    /// <param name="settings">Detection settings. Uses <see cref="EntropyDetectionSettings.Default"/> if null.</param>
    /// <returns>Collection of secret findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="lines"/> is null.</exception>
    public static IEnumerable<SecretFinding> Scan(
        string filePath,
        string[] lines,
        EntropyDetectionSettings? settings = null)
    {
        ArgumentNullException.ThrowIfNull(lines);

        settings ??= EntropyDetectionSettings.Default;

        if (lines.Length == 0)
        {
            yield break;
        }

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];

            // Skip empty lines
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            // Extract string literals from the line
            var stringLiterals = ExtractStringLiterals(line);

            foreach (string literal in stringLiterals)
            {
                // Skip if too short
                if (literal.Length < settings.MinLength)
                {
                    continue;
                }

                // Pre-filter: Exclude known non-secret patterns
                if (IsKnownNonSecretPattern(literal))
                {
                    continue;
                }

                // Determine character set and use appropriate threshold
                double effectiveThreshold = GetEffectiveThreshold(literal, settings);

                // Calculate entropy using ReadOnlySpan for better performance
                double entropy = ShannonEntropy(literal.AsSpan());

                // Check threshold
                if (entropy >= effectiveThreshold)
                {
                    // Check for assignment context keywords near the match
                    bool hasContext = HasAssignmentContext(line, literal, settings);

                    // Determine severity based on context
                    string severity = hasContext ? "High" : "Low";

                    yield return new SecretFinding
                    {
                        FilePath = filePath,
                        LineNumber = i + 1,
                        Rule = "EntropyDetector",
                        Secret = literal,
                        Severity = severity
                    };
                }
            }
        }
    }

    /// <summary>
    /// Determines the effective entropy threshold based on the string's character set.
    /// Hex strings and Base64 strings require different thresholds due to their inherent structure.
    /// </summary>
    /// <param name="s">The string to analyze.</param>
    /// <param name="settings">Detection settings.</param>
    /// <returns>The appropriate entropy threshold for the string type.</returns>
    private static double GetEffectiveThreshold(string s, EntropyDetectionSettings settings)
    {
        // Pure hex strings (GUIDs, hashes) need higher entropy
        if (IsHexOnly(s))
        {
            return settings.HexEntropyThreshold;
        }

        // Base64 strings need lower threshold (they're more structured)
        if (IsValidBase64(s))
        {
            return settings.Base64EntropyThreshold;
        }

        // Default threshold for other strings
        return settings.Threshold;
    }

    /// <summary>
    /// Checks if a string contains assignment context keywords nearby.
    /// This helps distinguish between legitimate secrets and random high-entropy strings.
    /// </summary>
    /// <param name="line">The line containing the potential secret.</param>
    /// <param name="secret">The potential secret string.</param>
    /// <param name="settings">Detection settings.</param>
    /// <returns>True if assignment context keywords are found near the secret.</returns>
    private static bool HasAssignmentContext(string line, string secret, EntropyDetectionSettings settings)
    {
        // Find the position of the secret in the line
        int secretIndex = line.IndexOf(secret, StringComparison.Ordinal);
        if (secretIndex == -1)
        {
            // Secret might be split across multiple lines or escaped, search entire line
            secretIndex = 0;
        }

        // Search within context window before and after the secret
        int start = Math.Max(0, secretIndex - settings.ContextWindow);
        int end = Math.Min(line.Length, secretIndex + secret.Length + settings.ContextWindow);
        string context = line[start..end];

        // Check for assignment context keywords
        foreach (string keyword in settings.ContextKeywords)
        {
            if (context.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if a string matches known non-secret patterns that should be excluded.
    /// This includes GUIDs, git SHAs, common hash lengths, and other identifiers.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string matches a known non-secret pattern.</returns>
    private static bool IsKnownNonSecretPattern(string s)
    {
        // Skip pure hex strings (GUIDs, hashes) - already handled by threshold, but double-check
        if (IsHexOnly(s))
        {
            return true;
        }

        // Check for GUID patterns (8-4-4-4-12 format)
        if (IsGuidPattern(s))
        {
            return true;
        }

        // Check for common hash lengths (SHA-256, SHA-1, MD5, etc.)
        if (IsCommonHashLength(s))
        {
            return true;
        }

        // Check for git commit SHAs (40 character hex)
        if (IsGitSha(s))
        {
            return true;
        }

        // Check for common non-secret base64 patterns
        if (IsCommonNonSecretBase64(s))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Checks if a string looks like a GUID.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string matches a GUID pattern.</returns>
    private static bool IsGuidPattern(string s)
    {
        // Standard GUID format: 8-4-4-4-12 hex digits with hyphens
        if (s.Length == 36)
        {
            return Regex.IsMatch(s,
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        }

        // Braced GUID format: {8-4-4-4-12}
        if (s.Length == 38 && s.StartsWith('{') && s.EndsWith('}'))
        {
            return Regex.IsMatch(s,
                "^\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\}$");
        }

        // GUID without hyphens (32 hex chars)
        if (s.Length == 32)
        {
            return Regex.IsMatch(s, "^[0-9a-fA-F]{32}$");
        }

        return false;
    }

    /// <summary>
    /// Checks if a string has a common hash length that's likely not a secret.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string has a common hash length.</returns>
    private static bool IsCommonHashLength(string s)
    {
        // Common hash lengths (hex-only)
        int hexLength = s.Count(c => char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));

        return hexLength switch
        {
            32 => true,   // MD5
            40 => true,   // SHA-1
            64 => true,   // SHA-256
            128 => true,  // SHA-512
            _ => false
        };
    }

    /// <summary>
    /// Checks if a string looks like a git commit SHA.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string looks like a git SHA.</returns>
    private static bool IsGitSha(string s)
    {
        // Git SHAs are 40 character hex strings
        if (s.Length == 40)
        {
            return Regex.IsMatch(s, "^[0-9a-f]{40}$");
        }

        return false;
    }

    /// <summary>
    /// Checks if a string is a common non-secret Base64 pattern.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string is a common non-secret Base64 pattern.</returns>
    private static bool IsCommonNonSecretBase64(string s)
    {
        // Check for base64-like patterns that are unlikely to be secrets
        // Common patterns: URL-safe base64, base64 with padding, etc.

        // Skip if too short to be a meaningful secret
        if (s.Length < 16)
        {
            return false;
        }

        // Check if it's valid base64 and has common non-secret characteristics
        if (IsValidBase64(s))
        {
            // Decode to check if it's a common non-secret pattern
            try
            {
                byte[] decoded = Convert.FromBase64String(s);

                // Check if decoded data looks like a common non-secret pattern
                // For example, small integers or common strings
                if (decoded.Length < 8)
                {
                    return true;
                }

                // Check if it's all zeros or repeating pattern
                bool allSame = true;
                byte first = decoded[0];
                foreach (byte b in decoded)
                {
                    if (b != first)
                    {
                        allSame = false;
                        break;
                    }
                }

                if (allSame)
                {
                    return true;
                }
            }
            catch
            {
                // If decoding fails, it's not base64
                return false;
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts string literals from a line of code.
    /// Supports both single and double quotes.
    /// </summary>
    /// <param name="line">The line to extract strings from.</param>
    /// <returns>Collection of extracted string literals.</returns>
    private static IEnumerable<string> ExtractStringLiterals(string line)
    {
        // Simple state machine to extract string literals
        bool inSingleQuote = false;
        bool inDoubleQuote = false;
        bool escapeNext = false;
        var currentLiteral = new StringBuilder();

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if (escapeNext)
            {
                currentLiteral.Append(c);
                escapeNext = false;
                continue;
            }

            // Handle escape sequences
            if (c == '\\')
            {
                escapeNext = true;
                continue;
            }

            // Handle single quotes
            if (c == '\'' && !inDoubleQuote)
            {
                if (inSingleQuote)
                {
                    // End of single-quoted string
                    inSingleQuote = false;
                    if (currentLiteral.Length > 0)
                    {
                        yield return currentLiteral.ToString();
                        currentLiteral.Clear();
                    }
                }
                else if (!inSingleQuote && !inDoubleQuote)
                {
                    // Start of single-quoted string
                    inSingleQuote = true;
                    currentLiteral.Clear();
                }
                continue;
            }

            // Handle double quotes
            if (c == '"' && !inSingleQuote)
            {
                if (inDoubleQuote)
                {
                    // End of double-quoted string
                    inDoubleQuote = false;
                    if (currentLiteral.Length > 0)
                    {
                        yield return currentLiteral.ToString();
                        currentLiteral.Clear();
                    }
                }
                else if (!inSingleQuote && !inDoubleQuote)
                {
                    // Start of double-quoted string
                    inDoubleQuote = true;
                    currentLiteral.Clear();
                }
                continue;
            }

            // Collect character if inside a string
            if (inSingleQuote || inDoubleQuote)
            {
                currentLiteral.Append(c);
            }
        }

        // If we're still in a string at the end, yield it
        if ((inSingleQuote || inDoubleQuote) && currentLiteral.Length > 0)
        {
            yield return currentLiteral.ToString();
        }
    }

    /// <summary>
    /// Checks if a string looks like base64 or contains common non-secret patterns.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string looks like base64-like patterns that are unlikely to be secrets.</returns>
    private static bool IsBase64Like(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return true;
        }

        return IsBase64Like(s.AsSpan());
    }

    /// <summary>
    /// Checks if a character span looks like base64 or contains common non-secret patterns.
    /// </summary>
    /// <param name="span">The character span to check.</param>
    /// <returns>True if the span looks like base64-like patterns that are unlikely to be secrets.</returns>
    private static bool IsBase64Like(ReadOnlySpan<char> span)
    {
        if (span.IsEmpty)
        {
            return true;
        }

        // Check for GUID pattern
        if (span.Length == 36 && span[8] == '-' && span[13] == '-' && span[18] == '-' && span[23] == '-')
        {
            return true;
        }

        // Check for common path patterns
        bool hasSlash = false;
        bool hasDotCom = false;
        bool hasDotNet = false;
        bool hasDotOrg = false;

        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            if (c == '/' || c == '\\')
            {
                hasSlash = true;
            }
            else if (i <= span.Length - 4 && span.Slice(i, 4).SequenceEqual(".com"))
            {
                hasDotCom = true;
            }
            else if (i <= span.Length - 4 && span.Slice(i, 4).SequenceEqual(".net"))
            {
                hasDotNet = true;
            }
            else if (i <= span.Length - 4 && span.Slice(i, 4).SequenceEqual(".org"))
            {
                hasDotOrg = true;
            }
        }

        if (hasSlash || hasDotCom || hasDotNet || hasDotOrg)
        {
            return true;
        }

        // Check for base64-like patterns (alphanumeric + some special chars)
        int alphanumericCount = 0;
        foreach (char c in span)
        {
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
            {
                alphanumericCount++;
            }
        }

        double ratio = (double)alphanumericCount / span.Length;

        // If most characters are alphanumeric/base64 chars, it's likely not a secret
        if (ratio > 0.85)
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Determines whether the string consists solely of hexadecimal characters.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string is hex-only.</returns>
    private static bool IsHexOnly(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return false;
        }

        return IsHexOnly(s.AsSpan());
    }

    /// <summary>
    /// Determines whether the character span consists solely of hexadecimal characters.
    /// </summary>
    /// <param name="span">The character span to check.</param>
    /// <returns>True if the span is hex-only.</returns>
    private static bool IsHexOnly(ReadOnlySpan<char> span)
    {
        foreach (char c in span)
        {
            if (!((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }

        return !span.IsEmpty;
    }

    /// <summary>
    /// Determines whether the string is a valid Base64 encoded value.
    /// </summary>
    /// <param name="s">The string to check.</param>
    /// <returns>True if the string is valid Base64.</returns>
    private static bool IsValidBase64(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
        {
            return false;
        }

        return IsValidBase64(s.AsSpan());
    }

    /// <summary>
    /// Determines whether the character span is a valid Base64 encoded value.
    /// </summary>
    /// <param name="span">The character span to check.</param>
    /// <returns>True if the span is valid Base64.</returns>
    private static bool IsValidBase64(ReadOnlySpan<char> span)
    {
        if (span.IsWhiteSpace())
        {
            return false;
        }

        // Base64 strings should have a length that is a multiple of 4
        if (span.Length % 4 != 0)
        {
            return false;
        }

        try
        {
            // Attempt to decode; if it succeeds, it's valid Base64
            // Convert.FromBase64String requires string, so we need to convert to string
            // This is the only method that still needs a string conversion due to API limitations
            Convert.FromBase64String(span.ToString());
            return true;
        }
        catch
        {
            return false;
        }
    }
}