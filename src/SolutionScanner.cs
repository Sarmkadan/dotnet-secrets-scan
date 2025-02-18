using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

public sealed class SolutionScanner
{
    private readonly IEnumerable<SecretRule> _rules;

    public SolutionScanner(IEnumerable<SecretRule> rules)
    {
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
    }

    public ScanResult Scan(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));
        }

        if (!Directory.Exists(rootPath))
        {
            throw new DirectoryNotFoundException($"Directory not found: {rootPath}");
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var findings = new List<SecretFinding>();
        var filesScanned = 0;

        try
        {
            var fileWalker = new FileWalker();
            var files = fileWalker.EnumerateFiles(rootPath);

            foreach (var filePath in files)
            {
                try
                {
                    var fileFindings = ProcessFile(filePath);
                    findings.AddRange(fileFindings);
                    filesScanned++;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Skip files we can't read
                    continue;
                }
            }
        }
        finally
        {
            stopwatch.Stop();
        }

        var scanResult = new ScanResult
        {
            Findings = findings,
            TotalFilesScanned = filesScanned,
            TotalLinesScanned = 0,
            ScanTimestamp = DateTimeOffset.UtcNow
        };

        return scanResult;
    }

    private List<SecretFinding> ProcessFile(string filePath)
    {
        var findings = new List<SecretFinding>();
        var fileContent = File.ReadAllText(filePath);
        var lines = File.ReadAllLines(filePath);

        foreach (var rule in _rules)
        {
            var matches = rule.Match(fileContent, lines);
            findings.AddRange(matches);
        }

        var entropyFindings = EntropyDetector.Scan(filePath, lines);
        findings.AddRange(entropyFindings);

        return findings;
    }
}

file static class SecretRuleExtensions
{
    public static IEnumerable<SecretFinding> Match(this SecretRule rule, string fileContent, string[] lines)
    {
        if (rule == null)
        {
            throw new ArgumentNullException(nameof(rule));
        }

        if (string.IsNullOrEmpty(fileContent))
        {
            yield break;
        }

        var regex = new Regex(rule.Pattern, RegexOptions.Compiled);
        var matches = regex.Matches(fileContent);

        foreach (Match match in matches)
        {
            if (match.Success && match.Index >= 0)
            {
                // Find the line number
                var lineNumber = 1;
                var pos = 0;
                for (int i = 0; i < lines.Length && pos <= match.Index; i++)
                {
                    if (pos + lines[i].Length >= match.Index)
                    {
                        lineNumber = i + 1;
                        break;
                    }
                    pos += lines[i].Length + 1; // +1 for newline
                }

                var secret = match.Value.Trim();
                if (!string.IsNullOrEmpty(secret))
                {
                    yield return new SecretFinding
                    {
                        FilePath = "", // Will be set by caller
                        Rule = rule.Id,
                        Secret = secret,
                        LineNumber = lineNumber,
                        Severity = rule.Severity.ToString()
                    };
                }
            }
        }
    }
}