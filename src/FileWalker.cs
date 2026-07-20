using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DotnetSecretsScan;

/// <summary>
/// Recursively walks file system to enumerate source files while excluding build artifacts and common directories.
/// </summary>
public sealed class FileWalker
{
    private readonly HashSet<string> _excludePatterns;
    private readonly long _maxFileSizeBytes;

    /// <summary>
    /// Gets the number of files that were skipped because they exceeded <see cref="MaxFileSizeBytes"/>.
    /// </summary>
    public int SkippedFileCount { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="FileWalker"/> class.
    /// </summary>
    /// <param name="excludeGlobs">Optional additional glob patterns to exclude from enumeration.</param>
    /// <param name="maxFileSizeBytes">
    /// Optional maximum file size (in bytes) to process. Files larger than this value will be skipped.
    /// Defaults to <c>long.MaxValue</c> (no size limit).
    /// </param>
    public FileWalker(IEnumerable<string>? excludeGlobs = null, long maxFileSizeBytes = long.MaxValue)
    {
        _excludePatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "bin",
            "obj",
            "node_modules",
            ".git"
        };

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

        _maxFileSizeBytes = maxFileSizeBytes;
    }

    /// <summary>
    /// Recursively enumerates files in the specified directory.
    /// </summary>
    /// <param name="rootPath">Root directory to start enumeration from.</param>
    /// <returns>Collection of file paths matching allowed extensions.</returns>
    /// <exception cref="ArgumentNullException">Thrown when rootPath is null.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when rootPath does not exist.</exception>
    public IEnumerable<string> EnumerateFiles(string rootPath)
    {
        if (rootPath == null)
        {
            throw new ArgumentNullException(nameof(rootPath));
        }

        if (!Directory.Exists(rootPath))
        {
            throw new DirectoryNotFoundException($"Directory not found: {rootPath}");
        }

        // Reset the skipped file counter for each new enumeration run.
        SkippedFileCount = 0;

        var searchOption = SearchOption.AllDirectories;
        var dirInfo = new DirectoryInfo(rootPath);

        return EnumerateFilesInternal(dirInfo, searchOption);
    }

    private IEnumerable<string> EnumerateFilesInternal(DirectoryInfo directory, SearchOption searchOption)
    {
        // EnumerateFiles is lazy: exceptions surface during iteration, not at the call site,
        // so a try/catch around the call alone would not protect the foreach below. Use
        // EnumerationOptions to skip inaccessible entries instead of aborting the whole scan.
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = searchOption == SearchOption.AllDirectories,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        IEnumerable<FileInfo> files = directory.EnumerateFiles("*", options);

        foreach (var file in files)
        {
            // Skip files that exceed the configured maximum size.
            if (file.Length > _maxFileSizeBytes)
            {
                SkippedFileCount++;
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

            foreach (var segment in pathSegments)
            {
                currentPath = string.IsNullOrEmpty(currentPath) ? segment : $"{currentPath}/{segment}";

                if (_excludePatterns.Contains(segment) || _excludePatterns.Contains(currentPath))
                {
                    isExcluded = true;
                    break;
                }
            }

            if (isExcluded)
            {
                continue;
            }

            var extension = file.Extension.ToLowerInvariant();
            if (extension is ".cs" or ".json" or ".config" or ".xml" or ".yml" or ".yaml" or ".env")
            {
                yield return file.FullName;
            }
        }
    }
}
