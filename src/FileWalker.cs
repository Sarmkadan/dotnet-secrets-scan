using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace DotnetSecretsScan;

/// <summary>
/// Recursively walks file system to enumerate source files while excluding build artifacts and common directories.
/// </summary>
public sealed class FileWalker
{
    private const int BinarySniffLength = 8192;

    private static readonly HashSet<string> DefaultDirectoryExclusions = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin",
        "obj",
        ".git",
        "node_modules"
    };

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll",
        ".exe",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".zip",
        ".pdf"
    };

    /// <summary>
    /// Default maximum file size, in bytes, that will be processed when no explicit cap is supplied.
    /// </summary>
    public const long DefaultMaxFileSizeBytes = 1024 * 1024;

    private readonly HashSet<string> _excludePatterns;
    private readonly HashSet<string> _excludedDirectories;
    private readonly long _maxFileSizeBytes;
    private readonly ILogger<FileWalker> _logger;
    private long _totalFilesScanned;
    private long _totalBytesScanned;

    /// <summary>
    /// Gets the number of files that were skipped because they exceeded the configured maximum size.
    /// </summary>
    public long SkippedFileCount { get; private set; }

    /// <summary>
    /// Gets the number of files that were skipped because they were detected as binary content.
    /// </summary>
    public long SkippedBinaryFileCount { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="FileWalker"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for structured logging. Defaults to NullLogger.</param>
    /// <param name="excludeGlobs">Optional additional glob patterns to exclude from enumeration.</param>
    /// <param name="maxFileSizeBytes">
    /// Optional maximum file size (in bytes) to process. Files larger than this value will be skipped.
    /// Defaults to <see cref="DefaultMaxFileSizeBytes"/> (1 MB).
    /// </param>
    /// <param name="excludedDirectories">
    /// Optional additional directory names to exclude. Names are matched against individual directory
    /// segments, case-insensitively, in addition to the default exclusions.
    /// </param>
    public FileWalker(
        ILogger<FileWalker>? logger = null,
        IEnumerable<string>? excludeGlobs = null,
        long maxFileSizeBytes = DefaultMaxFileSizeBytes,
        IEnumerable<string>? excludedDirectories = null)
    {
        _logger = logger ?? NullLogger<FileWalker>.Instance;
        _excludePatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _excludedDirectories = new HashSet<string>(DefaultDirectoryExclusions, StringComparer.OrdinalIgnoreCase);

        if (excludeGlobs != null)
        {
            foreach (var pattern in excludeGlobs)
            {
                if (!string.IsNullOrWhiteSpace(pattern))
                {
                    _excludePatterns.Add(pattern.TrimEnd('/', '\\'));
                }
            }
        }

        if (excludedDirectories != null)
        {
            foreach (var directoryName in excludedDirectories)
            {
                if (!string.IsNullOrWhiteSpace(directoryName))
                {
                    _excludedDirectories.Add(directoryName.Trim().TrimEnd('/', '\\'));
                }
            }
        }

        _maxFileSizeBytes = maxFileSizeBytes;

        // Reset counters for fresh instance
        SkippedFileCount = 0;
        SkippedBinaryFileCount = 0;
    }

    /// <summary>
    /// Recursively enumerates files in the specified directory.
    /// </summary>
    /// <param name="rootPath">Root directory to start enumeration from.</param>
    /// <param name="cancellationToken">A cancellation token to observe while enumerating files.</param>
    /// <returns>Collection of file paths matching allowed extensions.</returns>
    /// <exception cref="ArgumentNullException">Thrown when rootPath is null.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when rootPath does not exist.</exception>
    public IEnumerable<string> EnumerateFiles(string rootPath, CancellationToken cancellationToken = default)
    {
        if (rootPath == null)
        {
            throw new ArgumentNullException(nameof(rootPath));
        }

        if (!Directory.Exists(rootPath))
        {
            throw new DirectoryNotFoundException($"Directory not found: {rootPath}");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Reset counters for each new enumeration run
        SkippedFileCount = 0;
        SkippedBinaryFileCount = 0;
        _totalFilesScanned = 0;
        _totalBytesScanned = 0;

        var searchOption = SearchOption.AllDirectories;
        var dirInfo = new DirectoryInfo(rootPath);

        return EnumerateAndLog(EnumerateFilesInternal(dirInfo, searchOption, cancellationToken));
    }

    private IEnumerable<string> EnumerateFilesInternal(DirectoryInfo directory, SearchOption searchOption, CancellationToken cancellationToken)
    {
        // Log entering this directory at Debug level
        _logger.LogDebug("Entering directory: {Path}", directory.FullName);

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false, // We handle recursion manually
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        // Enumerate files in current directory
        IEnumerable<FileInfo> files;
        try
        {
            files = directory.EnumerateFiles("*", options);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Unauthorized access to directory: {Path}", directory.FullName);
            yield break;
        }

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Skip files that exceed the configured maximum size.
            if (file.Length > _maxFileSizeBytes)
            {
                SkippedFileCount++;
                _logger.LogWarning("Skipping file due to size: {Path} (size: {SizeBytes} bytes)", file.FullName, file.Length);
                continue;
            }

            var relativePath = file.FullName.Substring(directory.FullName.Length).TrimStart('/', '\\');
            var pathSegments = relativePath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);

            if (pathSegments.Length == 0)
            {
                continue;
            }

            var isExcluded = false;
            var currentPath = string.Empty;

            for (var segmentIndex = 0; segmentIndex < pathSegments.Length; segmentIndex++)
            {
                var segment = pathSegments[segmentIndex];
                currentPath = string.IsNullOrEmpty(currentPath) ? segment : $"{currentPath}/{segment}";

                var isDirectorySegment = segmentIndex < pathSegments.Length - 1;
                if ((isDirectorySegment && _excludedDirectories.Contains(segment))
                    || _excludePatterns.Contains(segment)
                    || _excludePatterns.Contains(currentPath))
                {
                    isExcluded = true;
                    break;
                }
            }

            if (isExcluded)
            {
                _logger.LogDebug("Skipping file due to exclusion: {Path}", file.FullName);
                continue;
            }

            var extension = file.Extension.ToLowerInvariant();
            if (extension is not (".cs" or ".json" or ".config" or ".xml" or ".yml" or ".yaml" or ".env") || BinaryExtensions.Contains(extension))
            {
                _logger.LogDebug("Skipping file due to extension: {Path}", file.FullName);
                continue;
            }

            if (IsLikelyBinary(file.FullName))
            {
                SkippedBinaryFileCount++;
                _logger.LogWarning("Skipping file due to binary content: {Path}", file.FullName);
                continue;
            }

            // Yield the file and log at Debug level
            _logger.LogDebug("Yielding file: {Path}", file.FullName);
            _totalFilesScanned++;
            _totalBytesScanned += file.Length;

            yield return file.FullName;
        }

        // Recurse into subdirectories if requested
        if (searchOption == SearchOption.AllDirectories)
        {
            IEnumerable<DirectoryInfo> subDirectories;
            try
            {
                subDirectories = directory.EnumerateDirectories("*", options);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized access to directory: {Path}", directory.FullName);
                yield break;
            }

            foreach (var subDir in subDirectories)
            {
                foreach (var file in EnumerateFilesInternal(subDir, searchOption, cancellationToken))
                {
                    yield return file;
                }
            }
        }
    }

    private IEnumerable<string> EnumerateAndLog(IEnumerable<string> source)
    {
        foreach (var item in source)
        {
            yield return item;
        }

        // Log final totals at Information level
        _logger.LogInformation("Scan completed: {FilesScanned} files scanned, {BytesScanned} bytes read, {FilesSkipped} files skipped",
            _totalFilesScanned, _totalBytesScanned, SkippedFileCount + SkippedBinaryFileCount);
    }

    /// <summary>
    /// Determines whether a file is likely binary by sniffing the first <see cref="BinarySniffLength"/> bytes
    /// for a NUL byte, a common heuristic for distinguishing text from binary content.
    /// </summary>
    /// <param name="filePath">The path to the file to inspect.</param>
    /// <returns><c>true</c> if the file appears to be binary or cannot be read; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or whitespace.</exception>
    public static bool IsLikelyBinary(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Span<byte> buffer = stackalloc byte[BinarySniffLength];
            var bytesRead = stream.Read(buffer);

            for (var i = 0; i < bytesRead; i++)
            {
                if (buffer[i] == 0)
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Treat unreadable files as binary so they are safely skipped rather than crashing the scan.
            return true;
        }
    }
}