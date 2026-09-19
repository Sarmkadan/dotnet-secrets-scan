using System;
using System.Threading;
using DotnetSecretsScan;

namespace DotnetSecretsScan.Tests;

public class EntropyDetectorTests
{
    public static void Main()
    {
        Console.WriteLine("Running EntropyDetector cancellation test...");
        
        var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            var findings = EntropyDetector.Scan(
                "test.cs",
                new[] { "secret = \"abc123def456ghi789jkl012mno345pqr678stu901vwx234yz\";" },
                settings: null,
                cancellationToken: cts.Token);
            
            // Consume the enumerable to trigger the cancellation check
            foreach (var _ in findings) { }
            
            Console.WriteLine("FAIL: Expected OperationCanceledException");
            Environment.Exit(1);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("PASS: OperationCanceledException thrown as expected");
            Environment.Exit(0);
        }
    }
}
