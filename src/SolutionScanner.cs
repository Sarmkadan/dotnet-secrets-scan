using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

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
	/// <param name="rootPath">The root directory path to scan.</param>
	/// <returns>A <see cref="ScanResult"/> containing all findings and statistics.</returns>
	/// <exception cref="ArgumentException">Thrown when <paramref name="rootPath"/> is null or whitespace.</exception>
	/// <exception cref="DirectoryNotFoundException">Thrown when the specified directory does not exist.</exception>
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
		long linesScanned = 0;

		try
		{
			var fileWalker = new FileWalker();
			var files = fileWalker.EnumerateFiles(rootPath);

			foreach (var filePath in files)
			{
				try
				{
					var fileFindings = ProcessFile(filePath, out var fileLines);
					findings.AddRange(fileFindings);
					filesScanned++;
					linesScanned += fileLines;
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
		var findings = new List<SecretFinding>();
		var fileContent = File.ReadAllText(filePath);
		var lines = File.ReadAllLines(filePath);
		lineCount = lines.Length;

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