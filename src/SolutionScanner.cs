using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DotnetSecretsScan;

/// <summary>
/// Scans .NET solution directories for secrets and sensitive information using configurable rules.
/// </summary>
public sealed class SolutionScanner
{
    /// <summary>
    /// The collection of secret detection rules to apply during scanning.
    /// </summary>
    private readonly IEnumerable<SecretRule> _rules;

    /// <summary>
    /// Initializes a new instance of the <see cref="SolutionScanner"/> class.
    /// </summary>
    /// <param name="rules">The collection of secret detection rules to use for scanning.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="rules"/> is null.</exception>
    public SolutionScanner(IEnumerable<SecretRule> rules)
    {
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
    }

    /// <summary>
    /// Scans the specified directory for secrets and sensitive information.
    /// </summary>
    /// <param name="rootPath">The root directory path to scan, or "-" to scan stdin.</param>
    /// <returns>A <see cref="ScanResult"/> containing all findings and statistics.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="rootPath"/> is null or whitespace.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when the specified directory does not exist.</exception>
    public ScanResult Scan(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));
        }

        if (rootPath == "-")
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var content = Console.In.ReadToEnd();
            var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            var findings = ProcessContent(content, lines, "<stdin>");
            stopwatch.Stop();
            return new ScanResult
            {
                Findings = findings,
                TotalFilesScanned = 1,
                TotalLinesScanned = lines.Length,
                ScanTimestamp = DateTimeOffset.UtcNow
            };
        }

        if (!Directory.Exists(rootPath))
        {
            throw new DirectoryNotFoundException($"Directory not found: {rootPath}");
        }

        var stopwatch_ = System.Diagnostics.Stopwatch.StartNew();
        var findingsBag = new ConcurrentBag<SecretFinding>();
        var filesScanned = 0;
        long linesScanned = 0;
        var processingErrors = 0;

        try
        {
            var fileWalker = new FileWalker();
            var files = fileWalker.EnumerateFiles(rootPath).ToList();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            Parallel.ForEachAsync(files, parallelOptions, async (filePath, cancellationToken) =>
            {
                try
                {
                    var fileFindings = ProcessFile(filePath, out var fileLines);
                    foreach (var finding in fileFindings)
                    {
                        findingsBag.Add(finding);
                    }
                    Interlocked.Increment(ref filesScanned);
                    Interlocked.Add(ref linesScanned, fileLines);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Skip files we can't read
                    Interlocked.Increment(ref processingErrors);
                }
            }).GetAwaiter().GetResult();
        }
        finally
        {
            stopwatch_.Stop();
        }

        var findingsList = findingsBag.ToList();
        findingsList.Sort((a, b) =>
        {
            var pathCompare = string.Compare(a.FilePath, b.FilePath, StringComparison.Ordinal);
            return pathCompare != 0
                ? pathCompare
                : a.LineNumber.CompareTo(b.LineNumber);
        });

        var scanResult = new ScanResult
        {
            Findings = findingsList,
            TotalFilesScanned = filesScanned,
            TotalLinesScanned = linesScanned,
            ScanTimestamp = DateTimeOffset.UtcNow
        };

        return scanResult;
    }

    /// <summary>
    /// Processes a single file to detect secrets using the configured rules and entropy analysis.
    /// </summary>
    /// <param name="filePath">The path to the file to process.</param>
    /// <param name="lineCount">Output parameter containing the total number of lines in the file.</param>
    /// <returns>A list of <see cref="SecretFinding"/> objects representing detected secrets.</returns>
    private List<SecretFinding> ProcessFile(string filePath, out int lineCount)
    {
        var fileContent = File.ReadAllText(filePath);
        var lines = File.ReadAllLines(filePath);
        lineCount = lines.Length;
        return ProcessContent(fileContent, lines, filePath);
    }

    /// <summary>
    /// Processes content to detect secrets using the configured rules and entropy analysis.
    /// </summary>
    /// <param name="fileContent">The content to scan.</param>
    /// <param name="lines">The lines of the content.</param>
    /// <param name="filePath">The path to associate with the findings.</param>
    /// <returns>A list of <see cref="SecretFinding"/> objects representing detected secrets.</returns>
    private List<SecretFinding> ProcessContent(string fileContent, string[] lines, string filePath)
    {
        var findings = new List<SecretFinding>();

        foreach (var rule in _rules)
        {
            var matches = rule.Match(fileContent, lines);
            foreach (var match in matches)
            {
                match.FilePath = filePath;
                findings.Add(match);
            }
        }

        var entropyFindings = EntropyDetector.Scan(filePath, lines);
        findings.AddRange(entropyFindings);

        // Honor "secrets-scan:ignore" comments (on the flagged line or the line above).
        return IgnoreCommentParser.Filter(findings, _ => lines).ToList();
    }
}

file static class SecretRuleExtensions
{
    /// <summary>
    /// Matches the secret pattern defined by the rule against file content.
    /// </summary>
    /// <param name="rule">The secret rule containing the pattern to match.</param>
    /// <param name="fileContent">The content of the file to scan.</param>
    /// <param name="lines">The lines of the file for line number calculation.</param>
    /// <returns>An enumerable of <see cref="SecretFinding"/> objects for each match found.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="rule"/> is null.</exception>
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