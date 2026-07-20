using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DotnetSecretsScan;

public static class EntropyDetector
{
    /// <summary>
    /// Calculates the Shannon entropy of a string.
    /// </summary>
    /// <param name="s">The input string.</param>
    /// <returns>The entropy value in bits.</returns>
    public static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return 0.0;
        }

        // Count frequency of each character
        var frequency = new Dictionary<char, int>();
        foreach (char c in s)
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
        int length = s.Length;

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
    /// <param name="threshold">Minimum entropy threshold to consider as a secret.</param>
    /// <param name="minLength">Minimum length of string to consider.</param>
    /// <returns>Collection of secret findings.</returns>
    public static IEnumerable<SecretFinding> Scan(
        string filePath,
        string[] lines,
        double threshold = 4.5,
        int minLength = 20)
    {
        if (lines == null || lines.Length == 0)
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
                if (literal.Length < minLength)
                {
                    continue;
                }

                // Skip pure hex strings (often GUIDs or hashes)
                if (IsHexOnly(literal))
                {
                    continue;
                }

                // Determine if the literal is a valid Base64 string
                bool isValidBase64 = IsValidBase64(literal);

                // Adjust threshold for strong Base64 candidates
                double effectiveThreshold = threshold;
                if (isValidBase64 && literal.Length >= 32)
                {
                    // Lower the threshold because long Base64 strings are more likely to be secrets
                    effectiveThreshold = Math.Max(0, threshold - 1.0);
                }
                else if (IsBase64Like(literal))
                {
                    // Skip other Base64‑like patterns that are unlikely to be secrets
                    continue;
                }

                // Calculate entropy
                double entropy = ShannonEntropy(literal);

                // Check threshold
                if (entropy >= effectiveThreshold)
                {
                    yield return new SecretFinding
                    {
                        FilePath = filePath,
                        LineNumber = i + 1,
                        Rule = "EntropyDetector",
                        Secret = literal,
                        Severity = "High"
                    };
                }
            }
        }
    }

    /// <summary>
    /// Extracts string literals from a line of code.
    /// Supports both single and double quotes.
    /// </summary>
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
    private static bool IsBase64Like(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return true;
        }

        // Check for GUID pattern
        if (s.Length == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-')
        {
            return true;
        }

        // Check for common path patterns
        if (s.Contains('/') || s.Contains('\\') || s.Contains(".com") || s.Contains(".net") || s.Contains(".org"))
        {
            return true;
        }

        // Check for base64-like patterns (alphanumeric + some special chars)
        int alphanumericCount = s.Count(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=');
        double ratio = (double)alphanumericCount / s.Length;

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
    private static bool IsHexOnly(string s)
    {
        return s.All(c =>
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
    }

    /// <summary>
    /// Determines whether the string is a valid Base64 encoded value.
    /// </summary>
    private static bool IsValidBase64(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
        {
            return false;
        }

        // Base64 strings should have a length that is a multiple of 4
        if (s.Length % 4 != 0)
        {
            return false;
        }

        try
        {
            // Attempt to decode; if it succeeds, it's valid Base64
            Convert.FromBase64String(s);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
