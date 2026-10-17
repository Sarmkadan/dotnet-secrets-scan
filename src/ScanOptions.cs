using System.Collections.Generic;

namespace DotnetSecretsScan;

/// <summary>
/// Configuration for a single scan run. Checked by <see cref="ScanOptionsValidator"/> before any file is enumerated.
/// </summary>
/// <param name="Root">Directory or file to scan, or <c>-</c> to read from stdin.</param>
/// <param name="OutputPath">Optional report file. When <see langword="null"/> or empty, the report goes to the console.</param>
/// <param name="EntropyThreshold">Shannon entropy threshold, in bits per character, that a token must reach to be reported.</param>
/// <param name="MinTokenLength">Minimum length of a token considered by entropy detection.</param>
/// <param name="ExcludeGlobs">Glob patterns for paths to skip during enumeration. Each pattern matches a path segment or a path prefix.</param>
public sealed record ScanOptions(
    string Root,
    string? OutputPath = null,
    double EntropyThreshold = 4.5,
    int MinTokenLength = 20,
    IReadOnlyList<string>? ExcludeGlobs = null);
