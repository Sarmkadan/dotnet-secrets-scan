using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
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
    /// <param name="cancellationToken">A cancellation token to observe while scanning.</param>
    /// <returns>A <see cref="ScanResult"/> containing all findings and statistics.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="rootPath"/> is null or whitespace.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when the specified directory does not exist.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled.</exception>
    public ScanResult Scan(string rootPath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (rootPath == "-")
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var content = Console.In.ReadToEnd();
            cancellationToken.ThrowIfCancellationRequested();
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
                MaxDegreeOfParallelism = Environment.ProcessorCount,
                CancellationToken = cancellationToken
            };

            Parallel.ForEachAsync(files, parallelOptions, async (filePath, _) =>
            {
                cancellationToken.ThrowIfCancellationRequested();

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

        // Sort findings deterministically by (FilePath, LineNumber, Rule) to ensure stable output
        // across multiple runs. This is critical for baseline file diffs and CI report diffs.
        findingsList.Sort((a, b) =>
        {
            var pathCompare = string.Compare(a.FilePath, b.FilePath, StringComparison.Ordinal);
            if (pathCompare != 0)
            {
                return pathCompare;
            }

            var lineCompare = a.LineNumber.CompareTo(b.LineNumber);
            if (lineCompare != 0)
            {
                return lineCompare;
            }

            return string.Compare(a.Rule, b.Rule, StringComparison.Ordinal);
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
    /// Asynchronously scans the specified directory for secrets and sensitive information.
    /// </summary>
    /// <param name="rootPath">The root directory path to scan, or "-" to scan stdin.</param>
    /// <param name="cancellationToken">A cancellation token to observe while scanning.</param>
    /// <returns>A <see cref="ScanResult"/> containing all findings and statistics.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="rootPath"/> is null or whitespace.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when the specified directory does not exist.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled.</exception>
    public async Task<ScanResult> ScanAsync(string rootPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);

        cancellationToken.ThrowIfCancellationRequested();

        if (rootPath == "-")
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var content = await Console.In.ReadToEndAsync();
            cancellationToken.ThrowIfCancellationRequested();
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
            cancellationToken.ThrowIfCancellationRequested();

            var fileWalker = new FileWalker();
            var files = fileWalker.EnumerateFiles(rootPath).ToList();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount,
                CancellationToken = cancellationToken
            };

            await Parallel.ForEachAsync(files, parallelOptions, async (filePath, _) =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var (fileFindings, fileLineCount) = await ProcessFileAsync(filePath);
                    foreach (var finding in fileFindings)
                    {
                        findingsBag.Add(finding);
                    }
                    Interlocked.Increment(ref filesScanned);
                    Interlocked.Add(ref linesScanned, fileLineCount);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Skip files we can't read
                    Interlocked.Increment(ref processingErrors);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            stopwatch_.Stop();
        }

        var findingsList = findingsBag.ToList();

        // Sort findings deterministically by (FilePath, LineNumber, Rule) to ensure stable output
        // across multiple runs. This is critical for baseline file diffs and CI report diffs.
        findingsList.Sort((a, b) =>
        {
            var pathCompare = string.Compare(a.FilePath, b.FilePath, StringComparison.Ordinal);
            if (pathCompare != 0)
            {
                return pathCompare;
            }

            var lineCompare = a.LineNumber.CompareTo(b.LineNumber);
            if (lineCompare != 0)
            {
                return lineCompare;
            }

            return string.Compare(a.Rule, b.Rule, StringComparison.Ordinal);
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
        var lines = ReadAllLinesStreaming(filePath);
        lineCount = lines.Length;
        var fileContent = string.Join('\n', lines);
        return ProcessContent(fileContent, lines, filePath);
    }

    /// <summary>
    /// Reads a text file line-by-line via a single streamed pass rather than buffering the whole
    /// file twice (once for raw content, once for the line array), reducing peak memory usage
    /// for large files.
    /// </summary>
    /// <param name="filePath">The path to the file to read.</param>
    /// <returns>An array containing every line of the file.</returns>
    private static string[] ReadAllLinesStreaming(string filePath)
    {
        var lines = new List<string>();
        using var reader = new StreamReader(filePath);
        while (reader.ReadLine() is { } line)
        {
            lines.Add(line);
        }

        return lines.ToArray();
    }

    /// <summary>
    /// Asynchronously reads a text file line-by-line via a single streamed pass rather than
    /// buffering the whole file twice (once for raw content, once for the line array), reducing
    /// peak memory usage for large files.
    /// </summary>
    /// <param name="filePath">The path to the file to read.</param>
    /// <returns>An array containing every line of the file.</returns>
    private static async Task<string[]> ReadAllLinesStreamingAsync(string filePath)
    {
        var lines = new List<string>();
        using var reader = new StreamReader(filePath);
        while (await reader.ReadLineAsync() is { } line)
        {
            lines.Add(line);
        }

        return lines.ToArray();
    }

    /// <summary>
    /// Asynchronously processes a single file to detect secrets using the configured rules and entropy analysis.
    /// </summary>
    /// <param name="filePath">The path to the file to process.</param>
    /// <returns>
    /// A tuple containing the list of <see cref="SecretFinding"/> objects representing detected secrets
    /// and the number of lines read from the file.
    /// </returns>
    private async Task<(List<SecretFinding> Findings, int LineCount)> ProcessFileAsync(string filePath)
    {
        var lines = await ReadAllLinesStreamingAsync(filePath);
        var fileContent = string.Join('\n', lines);
        return (ProcessContent(fileContent, lines, filePath), lines.Length);
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
    /// Per-file, per-rule regex match timeout. Bounds the worst case where a pathological rule
    /// pattern exhibits catastrophic backtracking against a particular file's content, without
    /// letting it hang the whole scan.
    /// </summary>
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Cache of compiled regexes keyed by pattern, so each rule's pattern is compiled once for
    /// the lifetime of the process instead of once per file.
    /// </summary>
    private static readonly ConcurrentDictionary<string, Regex?> CompiledRegexCache = new();

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

        var regex = GetCompiledRegex(rule.Pattern);
        if (regex is null)
        {
            // The pattern is invalid; skip this rule.
            yield break;
        }

        MatchCollection matches;
        try
        {
            matches = regex.Matches(fileContent);
        }
        catch (RegexMatchTimeoutException)
        {
            Console.Error.WriteLine(
                $"warning: rule '{rule.Id}' timed out after {MatchTimeout.TotalSeconds:0}s scanning content; skipping rule for this file.");
            yield break;
        }

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

    /// <summary>
    /// Gets or compiles (and caches) the regex for the given pattern.
    /// </summary>
    /// <param name="pattern">The regular expression pattern to compile.</param>
    /// <returns>The compiled <see cref="Regex"/>, or <c>null</c> if the pattern is invalid.</returns>
    private static Regex? GetCompiledRegex(string pattern) =>
        CompiledRegexCache.GetOrAdd(pattern, static p =>
        {
            try
            {
                return new Regex(p, RegexOptions.Compiled, MatchTimeout);
            }
            catch (ArgumentException)
            {
                return null;
            }
        });
}