namespace DotnetSecretsScan;

/// <summary>
/// Defines exit codes for the dotnet-secrets-scan tool.
/// </summary>
public static class ExitCodes
{
    /// <summary>
    /// Exit code indicating successful execution with no findings (clean scan).
    /// </summary>
    public const int Success = 0;

    /// <summary>
    /// Exit code indicating successful execution with findings detected.
    /// </summary>
    public const int Findings = 1;

    /// <summary>
    /// Exit code indicating a scan error occurred (e.g., invalid arguments, file access issues).
    /// </summary>
    public const int ScanError = 2;
}
