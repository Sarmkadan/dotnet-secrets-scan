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


    /// <summary>
    /// Initializes a new instance of the FileWalker class.
    /// </summary>
    /// <param name="excludeGlobs">Optional additional glob patterns to exclude from enumeration.</param>
    public FileWalker(IEnumerable<string>? excludeGlobs = null)
    {
        _excludePatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "bin/",
            "obj/",
            "node_modules/",
            ".git/"
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

        var searchOption = SearchOption.AllDirectories;
        var dirInfo = new DirectoryInfo(rootPath);

        return EnumerateFilesInternal(dirInfo, searchOption);
    }

    private IEnumerable<string> EnumerateFilesInternal(DirectoryInfo directory, SearchOption searchOption)
    {
        IEnumerable<FileInfo> files;
        try
        {
            files = directory.EnumerateFiles("*", searchOption);
        }
        catch (UnauthorizedAccessException)
        {
            yield break;
        }
        catch (PathTooLongException)
        {
            yield break;
        }
        catch (DirectoryNotFoundException)
        {
            yield break;
        }

        foreach (var file in files)
        {
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

                if (_excludePatterns.Contains(currentPath, StringComparer.OrdinalIgnoreCase))
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