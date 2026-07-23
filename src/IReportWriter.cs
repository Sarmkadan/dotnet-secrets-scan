using System.IO;

namespace DotnetSecretsScan;

/// <summary>
/// Defines a uniform contract for rendering a <see cref="ScanResult"/> into a specific
/// output format. Implementations are resolved by <see cref="FormatName"/> so that new
/// formats can be added without changing call sites that dispatch on the requested format.
/// </summary>
public interface IReportWriter
{
    /// <summary>
    /// Gets the format identifier used to select this writer (for example "csv" or "sarif").
    /// Comparisons against this value should be case-insensitive.
    /// </summary>
    string FormatName { get; }

    /// <summary>
    /// Renders the given scan result and writes it to the supplied <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="result">The scan result to render.</param>
    /// <param name="output">The writer that receives the rendered report.</param>
    void Write(ScanResult result, TextWriter output);
}
