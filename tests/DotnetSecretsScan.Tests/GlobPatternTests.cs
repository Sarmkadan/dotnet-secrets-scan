using Xunit;

namespace DotnetSecretsScan.Tests;

public class GlobPatternTests
{
    [Theory]
    [InlineData("*.min.js", "app.min.js", true)]
    [InlineData("*.min.js", "x/app.min.js", false)]
    [InlineData("**/*.min.js", "app.min.js", true)]
    [InlineData("**/*.min.js", "a/b/app.min.js", true)]
    [InlineData("**/*.min.js", "a/app.js", false)]
    [InlineData("tests/fixtures", "tests/fixtures", true)]
    [InlineData("tests/fixtures", "tests/fixtures2", false)]
    [InlineData("generated/**", "generated", true)]
    [InlineData("generated/**", "generated/deep/file.cs", true)]
    [InlineData("generated/**", "generatedx", false)]
    [InlineData("file?.cs", "file1.cs", true)]
    [InlineData("file?.cs", "file12.cs", false)]
    [InlineData("[!a]x", "bx", true)]
    [InlineData("[!a]x", "ax", false)]
    [InlineData("BIN", "bin", true)]
    [InlineData("tests\\fixtures", "tests/fixtures", true)]
    public void Compile_MatchesExpectedPaths(string glob, string candidate, bool expected)
    {
        var regex = GlobPattern.Compile(glob);

        Assert.Equal(expected, regex.IsMatch(candidate));
    }

    [Theory]
    [InlineData("[abc")]
    [InlineData("[]")]
    [InlineData("[z-a]")]
    [InlineData("src/{a,b}")]
    [InlineData("}")]
    [InlineData("")]
    [InlineData("/")]
    public void TryCompile_InvalidGlob_ReturnsFalseWithReason(string glob)
    {
        var ok = GlobPattern.TryCompile(glob, out var regex, out var error);

        Assert.False(ok);
        Assert.Null(regex);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void Compile_InvalidGlob_Throws()
    {
        Assert.Throws<System.ArgumentException>(() => GlobPattern.Compile("[abc"));
    }
}
