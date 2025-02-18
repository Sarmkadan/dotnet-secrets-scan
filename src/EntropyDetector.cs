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

                // Calculate entropy
                double entropy = ShannonEntropy(literal);

                // Skip base64-like patterns (GUIDs, paths, etc.)
                if (IsBase64Like(literal))
                {
                    continue;
                }

                // Check threshold
                if (entropy >= threshold)
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
}