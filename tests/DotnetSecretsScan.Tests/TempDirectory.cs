using System;
using System.IO;

namespace DotnetSecretsScan.Tests;

/// <summary>
/// A uniquely named directory under the system temp path that is deleted when disposed.
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"dss-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    /// <summary>
    /// Gets the full path of the temporary directory.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Writes a file relative to the temporary directory, creating intermediate directories as needed.
    /// </summary>
    public string WriteFile(string relativePath, string content = "")
    {
        var fullPath = System.IO.Path.Combine(Path, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
