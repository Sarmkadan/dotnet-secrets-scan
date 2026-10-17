using System.IO;
using System.Linq;
using Xunit;

namespace DotnetSecretsScan.Tests;

public class FileWalkerExcludeTests : System.IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    [Fact]
    public void EnumerateFiles_ExcludeGlobs_SkipMatchingSegmentsAndPrefixes()
    {
        _temp.WriteFile("keep.cs");
        _temp.WriteFile("app.min.json");
        _temp.WriteFile("nested/deeper/b.min.json");
        _temp.WriteFile("vendor/lib.cs");
        _temp.WriteFile("Generated/gen.cs");

        var walker = new FileWalker(
            excludeGlobs: new[] { "**/*.min.json", "vendor", "generated" });

        var files = walker.EnumerateFiles(_temp.Path).Select(Path.GetFileName).ToList();

        Assert.Equal(new[] { "keep.cs" }, files);
    }

    [Fact]
    public void EnumerateFiles_DefaultDirectoryExclusions_ApplyAtAnyDepth()
    {
        _temp.WriteFile("src/Service/Real.cs");
        _temp.WriteFile("src/Service/bin/Debug/Generated.cs");
        _temp.WriteFile("src/Service/obj/Temp.cs");

        var walker = new FileWalker();

        var files = walker.EnumerateFiles(_temp.Path).Select(Path.GetFileName).ToList();

        Assert.Equal(new[] { "Real.cs" }, files);
    }

    [Fact]
    public void EnumerateFiles_NoExcludeGlobs_ReturnsAllSupportedFiles()
    {
        _temp.WriteFile("keep.cs");
        _temp.WriteFile("vendor/lib.cs");

        var walker = new FileWalker();

        var files = walker.EnumerateFiles(_temp.Path).Select(Path.GetFileName).OrderBy(f => f).ToList();

        Assert.Equal(new[] { "keep.cs", "lib.cs" }, files);
    }
}
