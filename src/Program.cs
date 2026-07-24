using System;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DotnetSecretsScan.Verification;

namespace DotnetSecretsScan;

/// <summary>
/// Entry point for the dotnet-secrets-scan console application.
/// </summary>
public static class Program
{
    /// <summary>
    /// Main entry point for the application.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code: 0 for success, 1 for findings, 2 for scan error.</returns>
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = CreateRootCommand();
        return await rootCommand.InvokeAsync(args);
    }

    private static RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand(
            "Scans a .NET solution for leaked secrets in appsettings, code and connection strings.")
        {
            TreatUnmatchedTokensAsErrors = true
        };

        var pathArgument = new Argument<string>(
            "path",
            "Path to scan (directory, solution file, or '-' for stdin)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

        var outputOption = new Option<string>(
            new[] { "--output", "-o" },
            "Output file path (optional). If not specified, results are written to console.")
        {
            IsRequired = false
        };

        var formatOption = new Option<string>(
            new[] { "--format", "-f" },
            getDefaultValue: () => "console",
            "Output format: console, json, csv, sarif, junit. Default: console")
        {
            IsRequired = false
        };

        var verboseOption = new Option<bool>(
            new[] { "--verbose", "-v" },
            "Show detailed findings in console output")
        {
            IsRequired = false
        };

        var baselineOption = new Option<string>(
            new[] { "--baseline" },
            "Path to baseline file to filter findings")
        {
            IsRequired = false
        };

        var pruneBaselineOption = new Option<bool>(
            new[] { "--prune-baseline" },
            "Prune stale baseline entries and save the updated baseline")
        {
            IsRequired = false
        };

        var verifyOption = new Option<bool>(
            new[] { "--verify" },
            "Opt-in: make a live, read-only API call per AWS/GitHub/Slack finding to check whether the credential is still active")
        {
            IsRequired = false
        };

        rootCommand.AddArgument(pathArgument);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(formatOption);
        rootCommand.AddOption(verboseOption);
        rootCommand.AddOption(baselineOption);
        rootCommand.AddOption(pruneBaselineOption);
        rootCommand.AddOption(verifyOption);

        rootCommand.SetHandler(
            (path, outputPath, format, verbose, baselinePath, pruneBaseline, verify) =>
                RunScan(path, outputPath, format, verbose, baselinePath, pruneBaseline, verify),
            pathArgument,
            outputOption,
            formatOption,
            verboseOption,
            baselineOption,
            pruneBaselineOption,
            verifyOption);

        return rootCommand;
    }

    private static async Task<int> RunScan(
        string path,
        string? outputPath,
        string format,
        bool verbose,
        string? baselinePath,
        bool pruneBaseline,
        bool verify)
    {
        try
        {
            // Validate path
            if (string.IsNullOrWhiteSpace(path))
            {
                Console.Error.WriteLine("Error: Path cannot be null or whitespace.");
                return ExitCodes.ScanError;
            }

            if (path != "-" && !Directory.Exists(path) && !File.Exists(path))
            {
                Console.Error.WriteLine($"Error: Path '{path}' does not exist.");
                return ExitCodes.ScanError;
            }

            // Load baseline if specified
            BaselineFile? baseline = null;
            if (!string.IsNullOrWhiteSpace(baselinePath))
            {
                if (!File.Exists(baselinePath))
                {
                    Console.Error.WriteLine($"Error: Baseline file '{baselinePath}' does not exist.");
                    return ExitCodes.ScanError;
                }

                try
                {
                    baseline = BaselineFile.Load(baselinePath);

                    // Migrate old baseline format to new format (line-number independent)
                    if (pruneBaseline)
                    {
                        var migratedCount = baseline.MigrateFromLegacyFormat();
                        Console.WriteLine($"Migrated {migratedCount} baseline entries to new format.");
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error: Failed to load baseline file: {ex.Message}");
                    return ExitCodes.ScanError;
                }
            }

            // Create scanner with built-in rules
            var rules = BuiltInRules.All.Concat(CloudProviderRules.All).ToList();
            var scanner = new SolutionScanner(rules);

            // Perform scan
            ScanResult scanResult;
            try
            {
                scanResult = scanner.Scan(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
            {
                Console.Error.WriteLine($"Error: Failed to scan path '{path}': {ex.Message}");
                return ExitCodes.ScanError;
            }

            // Filter findings against baseline if provided
            var findings = scanResult.Findings;
            if (baseline != null)
            {
                findings = baseline.FilterNew(findings).ToList();
            }

            // Create result with filtered findings
            var result = new ScanResult
            {
                Findings = findings,
                TotalFilesScanned = scanResult.TotalFilesScanned,
                TotalLinesScanned = scanResult.TotalLinesScanned,
                ScanTimestamp = scanResult.ScanTimestamp
            };

            // Optionally verify findings against their issuing provider (live, opt-in, best-effort).
            if (verify)
            {
                await VerifyFindingsAsync(result.Findings);
            }

            // Determine exit code based on findings
            var exitCode = result.TotalFindings > 0 ? ExitCodes.Findings : ExitCodes.Success;

            // If prune-baseline is requested, update the baseline file
            if (pruneBaseline && baseline != null && !string.IsNullOrWhiteSpace(baselinePath))
            {
                try
                {
                    // Prune stale entries for each file that was scanned
                    var filesScanned = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var finding in scanResult.Findings)
                    {
                        filesScanned.Add(finding.FilePath);
                    }

                    var totalPruned = 0;
                    foreach (var filePath in filesScanned)
                    {
                        if (File.Exists(filePath))
                        {
                            var fileContent = await File.ReadAllTextAsync(filePath);
                            var prunedCount = baseline.PruneStaleEntries(filePath, fileContent);
                            totalPruned += prunedCount;
                        }
                    }

                    if (totalPruned > 0)
                    {
                        Console.WriteLine($"Pruned {totalPruned} stale baseline entries.");
                    }

                    // Save the updated baseline
                    baseline.Save(baselinePath);
                    Console.WriteLine($"Updated baseline saved to: {baselinePath}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error: Failed to prune baseline: {ex.Message}");
                    return ExitCodes.ScanError;
                }
            }

            // Write output
            try
            {
                var reportWriters = new Dictionary<string, IReportWriter>(StringComparer.OrdinalIgnoreCase)
                {
                    ["console"] = new ConsoleReportWriter(verbose),
                    ["json"] = new JsonReportWriter(),
                    ["csv"] = new CsvReportWriter(),
                    ["sarif"] = new SarifReportWriter(),
                    ["junit"] = new JUnitReportWriter(),
                    ["html"] = new HtmlReportWriter()
                };

                if (string.IsNullOrWhiteSpace(outputPath) || string.Equals(format, "console", StringComparison.OrdinalIgnoreCase))
                {
                    // Write to console
                    reportWriters["console"].Write(result, Console.Out);
                }
                else if (reportWriters.TryGetValue(format, out var writer))
                {
                    // Write to file
                    using var stringWriter = new StringWriter();
                    writer.Write(result, stringWriter);
                    await File.WriteAllTextAsync(outputPath, stringWriter.ToString());
                    Console.WriteLine($"Scan results written to: {outputPath}");
                }
                else
                {
                    Console.Error.WriteLine($"Warning: Unsupported format '{format}'. Using console output.");
                    reportWriters["console"].Write(result, Console.Out);
                    return exitCode;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Error: Failed to write output: {ex.Message}");
                return ExitCodes.ScanError;
            }

            // Print summary line
            var severityCounts = result.FindingsBySeverity;
            var severityParts = new List<string>();
            foreach (var severity in new[] { "Critical", "High", "Medium", "Low", "Info" })
            {
                if (severityCounts.TryGetValue(severity, out var count) && count > 0)
                {
                    severityParts.Add($"{severity}: {count}");
                }
            }

            var severitySummary = severityParts.Count > 0
                ? string.Join(", ", severityParts)
                : "No findings";

            Console.WriteLine();
            Console.WriteLine($"Summary: {result.TotalFilesScanned} files, {result.TotalLinesScanned} lines scanned, {result.TotalFindings} findings ({severitySummary})");

            return exitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitCodes.ScanError;
        }
    }

    /// <summary>
    /// Runs live, opt-in verification against every finding whose rule is eligible (AWS access
    /// keys, GitHub personal access tokens, Slack tokens) and stamps <see cref="SecretFinding.Verified"/>
    /// with the outcome. Verification is best-effort: any network or provider failure degrades a
    /// finding to "Unknown" rather than aborting the scan.
    /// </summary>
    /// <param name="findings">The findings to verify in place.</param>
    /// <exception cref="ArgumentNullException"><paramref name="findings"/> is <see langword="null"/>.</exception>
    private static async Task VerifyFindingsAsync(IReadOnlyList<SecretFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        using var verifier = new SecretVerifier();

        foreach (var finding in findings)
        {
            if (SecretVerifier.ResolveProvider(finding.Rule) is null)
            {
                continue;
            }

            var status = await verifier.VerifyAsync(finding);
            finding.Verified = status.ToString();
        }
    }
}