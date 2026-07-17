# ScanResult
The `ScanResult` type represents the outcome of a secrets scanning operation, encapsulating the findings, scan metrics, and timestamp. It provides a snapshot of the scanning process, allowing for further analysis, reporting, or serialization of the results.

## API
* `Findings`: A required, read-only list of `SecretFinding` objects, representing the secrets detected during the scan.
* `TotalFilesScanned`: An integer indicating the total number of files scanned.
* `TotalLinesScanned`: A long integer representing the total number of lines scanned.
* `ScanTimestamp`: A `DateTimeOffset` object specifying the timestamp when the scan was performed.
* `WriteConsole`: A static method that writes the scan result to the console. It does not take any parameters and does not return a value.
* `ToJson`: A static method that serializes the scan result to a JSON string. It does not take any parameters and returns a string.
* `ToSarif`: A static method that serializes the scan result to a SARIF (Static Analysis Results Interchange Format) string. It does not take any parameters and returns a string.

## Usage
The following examples demonstrate how to utilize the `ScanResult` type:
```csharp
// Example 1: Basic usage
var scanResult = new ScanResult(new List<SecretFinding>(), 10, 100, DateTimeOffset.Now);
Console.WriteLine(scanResult.Findings.Count); // Output: 0
Console.WriteLine(scanResult.TotalFilesScanned); // Output: 10
Console.WriteLine(scanResult.TotalLinesScanned); // Output: 100

// Example 2: Serializing to JSON
var findings = new List<SecretFinding> { new SecretFinding() };
var scanResultJson = ScanResult.ToJson(findings, 10, 100, DateTimeOffset.Now);
Console.WriteLine(scanResultJson); // Output: JSON representation of the scan result
```

## Notes
When working with `ScanResult`, consider the following edge cases and thread-safety remarks:
* The `Findings` list is read-only, ensuring that the scan result remains immutable once created.
* The `WriteConsole` method is thread-safe, as it only writes to the console and does not modify any shared state.
* The `ToJson` and `ToSarif` methods are also thread-safe, as they only perform serialization operations and do not access any shared state.
* When serializing `ScanResult` instances to JSON or SARIF, be aware that the resulting strings may contain sensitive information, such as secret findings. Handle these strings accordingly to prevent unintended disclosure of sensitive data.
