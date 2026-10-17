using System;
using System.IO;
using System.Linq;
using Xunit;

namespace DotnetSecretsScan.Tests;

public class ScanOptionsValidatorTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private ScanOptions ValidOptions(string? outputPath = null) =>
        new(Root: _temp.Path, OutputPath: outputPath, EntropyThreshold: 4.5, MinTokenLength: 20);

    [Fact]
    public void Validate_ValidOptions_ReturnsNoErrors()
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions());

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(4.5)]
    [InlineData(8.0)]
    public void Validate_EntropyThresholdInsideRange_IsAccepted(double threshold)
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions() with { EntropyThreshold = threshold });

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(-0.001)]
    [InlineData(8.001)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void Validate_EntropyThresholdOutsideRange_ReportsThreshold(double threshold)
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions() with { EntropyThreshold = threshold });

        var error = Assert.Single(errors);
        Assert.Contains("--entropy-threshold", error);
        Assert.Contains("between 0 and 8", error);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(20)]
    public void Validate_MinTokenLengthAtOrAboveFloor_IsAccepted(int minTokenLength)
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions() with { MinTokenLength = minTokenLength });

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(7)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_MinTokenLengthBelowFloor_ReportsMinTokenLength(int minTokenLength)
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions() with { MinTokenLength = minTokenLength });

        var error = Assert.Single(errors);
        Assert.Contains("--min-token-length must be at least 8", error);
    }

    [Fact]
    public void Validate_RootDirectoryMissing_ReportsRoot()
    {
        var missing = Path.Combine(_temp.Path, "does-not-exist");

        var errors = ScanOptionsValidator.Validate(new ScanOptions(missing));

        var error = Assert.Single(errors);
        Assert.Contains("does not exist", error);
        Assert.Contains(missing, error);
    }

    [Fact]
    public void Validate_RootIsExistingFile_IsAccepted()
    {
        var file = _temp.WriteFile("appsettings.json", "{}");

        var errors = ScanOptionsValidator.Validate(new ScanOptions(file));

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_StdinRoot_IsAccepted()
    {
        var errors = ScanOptionsValidator.Validate(new ScanOptions("-"));

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_OutputInExistingDirectory_IsAccepted()
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions(Path.Combine(_temp.Path, "report.json")));

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_OutputDirectoryMissing_ReportsOutputDirectory()
    {
        var output = Path.Combine(_temp.Path, "missing", "report.json");

        var errors = ScanOptionsValidator.Validate(ValidOptions(output));

        var error = Assert.Single(errors);
        Assert.Contains("Output directory", error);
        Assert.Contains("does not exist", error);
    }

    [Fact]
    public void Validate_OutputDirectoryNotWritable_ReportsOutputDirectory()
    {
        var output = Path.Combine(_temp.Path, "report.json");

        // Injected probe: root can write to any directory, so the real probe cannot exercise this branch.
        var errors = ScanOptionsValidator.Validate(ValidOptions(output), isDirectoryWritable: _ => false);

        var error = Assert.Single(errors);
        Assert.Contains("is not writable", error);
        Assert.Contains(_temp.Path, error);
    }

    [Fact]
    public void Validate_OutputPathIsExistingDirectory_ReportsOutputPath()
    {
        var subdirectory = Path.Combine(_temp.Path, "reports");
        Directory.CreateDirectory(subdirectory);

        var errors = ScanOptionsValidator.Validate(ValidOptions(subdirectory));

        var error = Assert.Single(errors);
        Assert.Contains("is a directory", error);
    }

    [Fact]
    public void Validate_NoOutputPath_DoesNotProbeWritability()
    {
        var errors = ScanOptionsValidator.Validate(
            ValidOptions(),
            isDirectoryWritable: _ => throw new InvalidOperationException("probe should not run"));

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData("[abc")]
    [InlineData("[]")]
    [InlineData("[z-a]")]
    [InlineData("src/{a,b}")]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_MalformedExcludeGlob_ReportsGlob(string glob)
    {
        var errors = ScanOptionsValidator.Validate(ValidOptions() with { ExcludeGlobs = new[] { glob } });

        var error = Assert.Single(errors);
        Assert.Contains("--exclude", error);
        Assert.Contains("not a valid glob", error);
    }

    [Fact]
    public void Validate_WellFormedExcludeGlobs_AreAccepted()
    {
        var options = ValidOptions() with
        {
            ExcludeGlobs = new[] { "**/*.min.js", "tests/fixtures", "generated/**", "file?.cs" }
        };

        var errors = ScanOptionsValidator.Validate(options);

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_MultipleViolations_ReturnsAllOfThemTogether()
    {
        var options = new ScanOptions(
            Root: Path.Combine(_temp.Path, "missing-root"),
            OutputPath: Path.Combine(_temp.Path, "missing-dir", "report.json"),
            EntropyThreshold: 9.0,
            MinTokenLength: 3,
            ExcludeGlobs: new[] { "[unclosed", "**/*.min.js" });

        var errors = ScanOptionsValidator.Validate(options);

        Assert.Equal(5, errors.Count);
        Assert.Single(errors, e => e.Contains("--entropy-threshold"));
        Assert.Single(errors, e => e.Contains("--min-token-length"));
        Assert.Single(errors, e => e.Contains("Scan path"));
        Assert.Single(errors, e => e.Contains("Output directory"));
        Assert.Single(errors, e => e.Contains("[unclosed"));
        Assert.Equal(5, errors.Distinct().Count());
    }
}
