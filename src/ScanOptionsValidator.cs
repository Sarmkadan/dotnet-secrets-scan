using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace DotnetSecretsScan;

/// <summary>
/// Validates <see cref="ScanOptions"/> up front so that an invalid configuration fails fast with a clear
/// message instead of producing a misleading scan.
/// </summary>
/// <remarks>
/// Every violation is collected and returned together, so a user can fix all problems in one pass.
/// </remarks>
public static class ScanOptionsValidator
{
    /// <summary>
    /// Lowest accepted entropy threshold, in bits per character.
    /// </summary>
    public const double MinEntropyThreshold = 0;

    /// <summary>
    /// Highest accepted entropy threshold, in bits per character. A byte-oriented token cannot exceed 8 bits.
    /// </summary>
    public const double MaxEntropyThreshold = 8;

    /// <summary>
    /// Smallest accepted minimum token length. Shorter tokens produce too many false positives to be useful.
    /// </summary>
    public const int MinTokenLengthFloor = 8;

    private const string StdinRoot = "-";
    private const string WriteProbePrefix = ".dss-write-probe-";

    /// <summary>
    /// Validates the options and returns every violation found.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <param name="isDirectoryWritable">
    /// Optional probe that reports whether a new file can be created in a directory. Defaults to creating and
    /// immediately deleting a temporary file in that directory.
    /// </param>
    /// <returns>A list of human-readable violations. The list is empty when the options are valid.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<string> Validate(ScanOptions options, Func<string, bool>? isDirectoryWritable = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var errors = new List<string>();

        if (!double.IsFinite(options.EntropyThreshold)
            || options.EntropyThreshold < MinEntropyThreshold
            || options.EntropyThreshold > MaxEntropyThreshold)
        {
            errors.Add(
                $"--entropy-threshold must be between {Format(MinEntropyThreshold)} and {Format(MaxEntropyThreshold)} bits, got {Format(options.EntropyThreshold)}.");
        }

        if (options.MinTokenLength < MinTokenLengthFloor)
        {
            errors.Add(
                $"--min-token-length must be at least {MinTokenLengthFloor}, got {options.MinTokenLength.ToString(CultureInfo.InvariantCulture)}.");
        }

        ValidateRoot(options.Root, errors);
        ValidateOutputPath(options.OutputPath, isDirectoryWritable ?? IsDirectoryWritable, errors);

        if (options.ExcludeGlobs is not null)
        {
            foreach (var glob in options.ExcludeGlobs)
            {
                if (!GlobPattern.TryCompile(glob, out _, out var error))
                {
                    errors.Add($"--exclude '{glob}' is not a valid glob: {error}.");
                }
            }
        }

        return errors;
    }

    private static void ValidateRoot(string? root, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            errors.Add("Scan path cannot be empty.");
            return;
        }

        // "-" reads from stdin and is not a file system path, so it has nothing to check.
        if (root == StdinRoot)
        {
            return;
        }

        if (!Directory.Exists(root) && !File.Exists(root))
        {
            errors.Add($"Scan path '{root}' does not exist.");
        }
    }

    private static void ValidateOutputPath(string? outputPath, Func<string, bool> isDirectoryWritable, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return;
        }

        string fullPath;
        string? directory;
        try
        {
            fullPath = Path.GetFullPath(outputPath);
            directory = Path.GetDirectoryName(fullPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            errors.Add($"Output path '{outputPath}' is not a valid path.");
            return;
        }

        if (Directory.Exists(fullPath))
        {
            errors.Add($"Output path '{outputPath}' is a directory; it must be a file path.");
            return;
        }

        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            errors.Add($"Output directory '{directory}' does not exist.");
            return;
        }

        if (!isDirectoryWritable(directory))
        {
            errors.Add($"Output directory '{directory}' is not writable.");
        }
    }

    private static bool IsDirectoryWritable(string directory)
    {
        try
        {
            var probePath = Path.Combine(directory, $"{WriteProbePrefix}{Guid.NewGuid():N}.tmp");
            using var probe = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1,
                FileOptions.DeleteOnClose);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Format(double value) =>
        value.ToString("0.###", CultureInfo.InvariantCulture);
}
