using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotnetSecretsScan.Tests;

// Redirects the process-wide Console.Error, so these tests must not run in parallel with each other.
[Collection("ProcessConsole")]
public class ProgramExitCodeTests : System.IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly TextWriter _originalError = System.Console.Error;

    public void Dispose()
    {
        System.Console.SetError(_originalError);
        _temp.Dispose();
    }

    [Fact]
    public async Task Main_InvalidConfig_ReturnsScanErrorAndReportsEveryViolation()
    {
        var stderr = new StringWriter();
        System.Console.SetError(stderr);

        var exitCode = await Program.Main(new[]
        {
            Path.Combine(_temp.Path, "missing"),
            "--entropy-threshold", "9",
            "--min-token-length", "3"
        });

        Assert.Equal(ExitCodes.ScanError, exitCode);
        var output = stderr.ToString();
        Assert.Contains("invalid scan options", output);
        Assert.Contains("--entropy-threshold", output);
        Assert.Contains("--min-token-length", output);
        Assert.Contains("does not exist", output);
    }

    [Fact]
    public async Task Main_NonNumericThreshold_ReturnsScanErrorNotFindings()
    {
        var stderr = new StringWriter();
        System.Console.SetError(stderr);

        var exitCode = await Program.Main(new[] { _temp.Path, "--entropy-threshold", "abc" });

        Assert.Equal(ExitCodes.ScanError, exitCode);
        Assert.Contains("Error:", stderr.ToString());
    }
}
