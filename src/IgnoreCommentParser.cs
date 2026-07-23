namespace DotnetSecretsScan;

/// <summary>
/// Parser for ignore comments in source files.
/// Supports inline ignore comments: // secrets-scan:ignore, # secrets-scan:ignore, <!-- secrets-scan:ignore -->
/// </summary>
public static class IgnoreCommentParser
{
    /// <summary>
    /// Checks if a single line should be ignored based on its content.
    /// </summary>
    /// <param name="lineContent">The line content to check</param>
    /// <returns>True if the line should be ignored; otherwise false</returns>
    public static bool IsLineIgnored(string lineContent)
    {
        ArgumentNullException.ThrowIfNull(lineContent);

        if (string.IsNullOrWhiteSpace(lineContent))
        {
            return false;
        }

        var trimmed = lineContent.Trim();

        // Check for C# style comments
        if (trimmed.StartsWith("// secrets-scan:ignore", StringComparison.Ordinal))
        {
            return true;
        }

        // Check for shell style comments
        if (trimmed.StartsWith("# secrets-scan:ignore", StringComparison.Ordinal))
        {
            return true;
        }

        // Check for HTML/XML style comments
        if (trimmed.StartsWith("<!-- secrets-scan:ignore", StringComparison.Ordinal) && trimmed.EndsWith("-->", StringComparison.Ordinal))
        {
            return true;
        }

        // Check for 'ignore next line' comments
        if (trimmed.StartsWith("// secrets-scan:ignore-next-line", StringComparison.Ordinal))
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Checks if a line should be ignored, considering comments on the previous line.
    /// This handles cases where the ignore comment appears on the line before the secret.
    /// </summary>
    /// <param name="fileLines">All lines of the file</param>
    /// <param name="lineNumber">1-based line number to check (lineNumber - 1 is checked for ignore comment)</param>
    /// <returns>True if the line should be ignored; otherwise false</returns>
    public static bool IsLineIgnored(string[] fileLines, int lineNumber)
    {
        ArgumentNullException.ThrowIfNull(fileLines);
        if (lineNumber < 1 || lineNumber > fileLines.Length)
        {
            return false;
        }

        // First, check if current line itself is an ignore comment
        if (IsLineIgnored(fileLines[lineNumber - 1]))
        {
            return true;
        }

        // Check previous line for ignore comment
        if (lineNumber > 1)
        {
            var previousLine = fileLines[lineNumber - 2];
            if (IsLineIgnored(previousLine))
            {
                return true;
            }
        }

        // Check for 'ignore next line' comments
        if (lineNumber > 1)
        {
            var previousLine = fileLines[lineNumber - 2];
            if (previousLine.Trim().StartsWith("// secrets-scan:ignore-next-line", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Filters a list of secret findings, removing those that should be ignored.
    /// </summary>
    /// <param name="findings">List of secret findings to filter</param>
    /// <param name="fileReader">Function to read file lines by path</param>
    /// <returns>Filtered list of secret findings with ignored ones removed</returns>
    public static IReadOnlyList<SecretFinding> Filter(IReadOnlyList<SecretFinding> findings, Func<string, string[]> fileReader)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(fileReader);

        if (findings.Count == 0)
        {
            return Array.Empty<SecretFinding>();
        }

        var filtered = new List<SecretFinding>(findings.Count);

        foreach (var finding in findings)
        {
            try
            {
                var lines = fileReader(finding.FilePath);
                if (lines != null && lines.Length >= finding.LineNumber)
                {
                    if (!IsLineIgnored(lines, finding.LineNumber))
                    {
                        filtered.Add(finding);
                    }
                }
                else
                {
                    // If we can't read the file, include the finding
                    filtered.Add(finding);
                }
            }
            catch
            {
                // If file reading fails, include the finding
                filtered.Add(finding);
            }
        }

        return filtered.AsReadOnly();
    }

    /// <summary>
    /// Checks if a JSON line should be ignored based on its content.
    /// </summary>
    /// <param name="lineContent">The line content to check</param>
    /// <returns>True if the line should be ignored; otherwise false</returns>
    public static bool IsJsonLineIgnored(string lineContent)
    {
        ArgumentNullException.ThrowIfNull(lineContent);

        if (string.IsNullOrWhiteSpace(lineContent))
        {
            return false;
        }

        var trimmed = lineContent.Trim();

        // Check for JSON compatible suppression via a sibling key
        if (trimmed.StartsWith("\"secrets-scan:ignore\"", StringComparison.Ordinal))
        {
            return true;
        }

        // Check for JSON compatible suppression via a trailing-line comment mode
        if (trimmed.EndsWith("// secrets-scan:ignore", StringComparison.Ordinal))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Checks if a YAML line should be ignored based on its content.
    /// </summary>
    /// <param name="lineContent">The line content to check</param>
    /// <returns>True if the line should be ignored; otherwise false</returns>
    public static bool IsYamlLineIgnored(string lineContent)
    {
        ArgumentNullException.ThrowIfNull(lineContent);

        if (string.IsNullOrWhiteSpace(lineContent))
        {
            return false;
        }

        var trimmed = lineContent.Trim();

        // Check for YAML compatible suppression via a sibling key
        if (trimmed.StartsWith("secrets-scan:ignore", StringComparison.Ordinal))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Filters a list of secret findings, removing those that should be ignored based on the rule ID.
    /// </summary>
    /// <param name="findings">List of secret findings to filter</param>
    /// <param name="fileReader">Function to read file lines by path</param>
    /// <param name="ruleId">The ID of the rule to filter by</param>
    /// <returns>Filtered list of secret findings with ignored ones removed</returns>
    public static IReadOnlyList<SecretFinding> FilterByRuleId(IReadOnlyList<SecretFinding> findings, Func<string, string[]> fileReader, string ruleId)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(fileReader);
        ArgumentNullException.ThrowIfNull(ruleId);

        if (findings.Count == 0)
        {
            return Array.Empty<SecretFinding>();
        }

        var filtered = new List<SecretFinding>(findings.Count);

        foreach (var finding in findings)
        {
            try
            {
                var lines = fileReader(finding.FilePath);
                if (lines != null && lines.Length >= finding.LineNumber)
                {
                    if (finding.Rule == ruleId && !IsLineIgnored(lines, finding.LineNumber))
                    {
                        filtered.Add(finding);
                    }
                }
                else
                {
                    // If we can't read the file, include the finding
                    filtered.Add(finding);
                }
            }
            catch
            {
                // If file reading fails, include the finding
                filtered.Add(finding);
            }
        }

        return filtered.AsReadOnly();
    }
}
