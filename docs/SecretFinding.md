# SecretFinding

Represents a single secret detection result produced by a scan. Each instance captures the exact location, the rule that triggered the detection, the secret content itself, and a severity classification. The type also provides fingerprinting for deduplication, equality comparison, and serves as the element type for `BaselineFile` collections that track known findings across scan runs.

## API

### Properties

- **`public required string FilePath`**  
  The absolute or relative path to the file where the secret was found. This property must be set during construction.

- **`public required int LineNumber`**  
  The one-based line number within the file where the secret starts. This property must be set during construction.

- **`public required string Rule`**  
  The identifier of the detection rule that matched the secret (e.g., `"generic-api-key"`, `"azure-connection-string"`). This property must be set during construction.

- **`public required string Secret`**  
  The raw secret string that was detected. This property must be set during construction.

- **`public required string Severity`**  
  The severity level assigned to the finding. Typical values include `"critical"`, `"high"`, `"medium"`, or `"low"`. This property must be set during construction.

### Instance Methods

- **`public string ComputeFingerprint()`**  
  Computes a stable, deterministic fingerprint for this finding based on its content and location. The fingerprint is suitable for identifying the same logical secret across different scan runs, even if minor contextual details change. Returns a string that can be compared with fingerprints from other findings.

- **`public bool Equals(SecretFinding? other)`**  
  Implements `IEquatable<SecretFinding>`. Compares this finding with another for value equality. Returns `true` if the two instances represent the same finding; otherwise `false`. The comparison logic typically considers the fingerprint or a combination of key fields.

- **`public override bool Equals(object? obj)`**  
  Overrides `Object.Equals`. Delegates to the typed `Equals(SecretFinding?)` method when `obj` is a `SecretFinding`; otherwise returns `false`.

- **`public override int GetHashCode()`**  
  Overrides `Object.GetHashCode()`. Returns a hash code consistent with the equality implementation, allowing `SecretFinding` instances to be used correctly in hash-based collections.

### Static Methods

- **`public static string ComputeFingerprint(string rule, string secret, string filePath, int lineNumber)`**  
  Computes a fingerprint directly from the constituent parts of a finding without requiring an instance. Accepts the rule identifier, secret string, file path, and line number. Returns the same deterministic fingerprint string that the instance method would produce for equivalent values. Useful when constructing fingerprints for lookups before creating full `SecretFinding` objects.

- **`public static BaselineFile Load(string filePath)`**  
  Deserializes a baseline file from the given path and returns it as a `BaselineFile` instance. The returned `BaselineFile` contains zero or more `SecretFinding` entries representing previously triaged results. Throws if the file does not exist, cannot be read, or contains invalid JSON that does not conform to the expected baseline schema.

- **`public static BaselineFile FromJson(string json)`**  
  Parses a JSON string directly and returns a `BaselineFile` instance. The JSON must conform to the baseline file schema. Throws if the string is null, empty, or malformed in a way that prevents deserialization into the expected structure.

### Methods on `BaselineFile` (Returned by `Load` / `FromJson`)

- **`public void Add(SecretFinding finding)`**  
  Adds a new `SecretFinding` to the baseline. If a finding with an identical fingerprint already exists, the behavior is implementation-defined (typically either replaces or ignores the duplicate). Throws if `finding` is null.

- **`public bool Contains(SecretFinding finding)`**  
  Checks whether the baseline already contains a finding with the same fingerprint as the provided `finding`. Returns `true` if a match exists; otherwise `false`. Throws if `finding` is null.

- **`public IReadOnlyList<SecretFinding> FilterNew(IEnumerable<SecretFinding> scanResults)`**  
  Compares a set of scan results against the current baseline and returns only those findings that are *new* — i.e., not already present in the baseline. Each finding in `scanResults` is checked by fingerprint. Returns a read-only list of new `SecretFinding` instances. Throws if `scanResults` is null.

- **`public void Save(string filePath)`**  
  Serializes the current baseline (including all added findings) to the specified file path as JSON. Overwrites the file if it already exists. Throws if the path is invalid, the directory does not exist, or write permissions are insufficient.

- **`public string ToJson()`**  
  Serializes the current baseline to a JSON string and returns it. Never returns null; an empty baseline produces a valid JSON representation of an empty collection.

## Usage

### Example 1: Creating findings and building a baseline

```csharp
// Create findings from scan results
var finding1 = new SecretFinding
{
    FilePath = @"C:\src\appsettings.json",
    LineNumber = 12,
    Rule = "generic-api-key",
    Secret = "sk-abc123def456",
    Severity = "high"
};

var finding2 = new SecretFinding
{
    FilePath = @"C:\src\config.yaml",
    LineNumber = 7,
    Rule = "azure-connection-string",
    Secret = "DefaultEndpointsProtocol=https;AccountName=...",
    Severity = "critical"
};

// Compute fingerprints for logging or deduplication
string fp1 = finding1.ComputeFingerprint();
string fp2 = finding2.ComputeFingerprint();

// Create a new baseline and add triaged findings
var baseline = new BaselineFile();
baseline.Add(finding1);
baseline.Add(finding2);

// Persist the baseline
baseline.Save(@"C:\src\.secrets-baseline.json");
```

### Example 2: Filtering new findings against an existing baseline

```csharp
// Load the existing baseline
BaselineFile baseline = BaselineFile.Load(@"C:\src\.secrets-baseline.json");

// Simulate a new scan run
var scanResults = new List<SecretFinding>
{
    new SecretFinding
    {
        FilePath = @"C:\src\appsettings.json",
        LineNumber = 12,
        Rule = "generic-api-key",
        Secret = "sk-abc123def456",
        Severity = "high"
    },
    new SecretFinding
    {
        FilePath = @"C:\src\repository.cs",
        LineNumber = 45,
        Rule = "github-token",
        Secret = "ghp_newToken789",
        Severity = "critical"
    }
};

// Get only findings not already in the baseline
IReadOnlyList<SecretFinding> newFindings = baseline.FilterNew(scanResults);

foreach (var finding in newFindings)
{
    Console.WriteLine($"New secret found: {finding.Rule} in {finding.FilePath}:{finding.LineNumber}");
}

// Optionally add the new findings to the baseline after triage
foreach (var finding in newFindings)
{
    baseline.Add(finding);
}

baseline.Save(@"C:\src\.secrets-baseline.json");
```

## Notes

- **Fingerprint stability**: The fingerprint computed by both `ComputeFingerprint` overloads is deterministic and depends on the rule, secret content, file path, and line number. Changes to any of these inputs will produce a different fingerprint. Callers should not rely on the internal format of the fingerprint string; it is intended only for equality comparisons.
- **Equality semantics**: Two `SecretFinding` instances are considered equal if they produce the same fingerprint. This means findings with identical rule, secret, file path, and line number are treated as duplicates even if other metadata differs.
- **Null handling**: Methods on `BaselineFile` (`Add`, `Contains`, `FilterNew`) throw when passed null arguments. The static `Load` and `FromJson` methods throw on null or invalid input. The `Equals` methods handle null gracefully (returning `false` for null comparisons).
- **Thread safety**: `SecretFinding` is an immutable record-like type once constructed and is safe to read from multiple threads. `BaselineFile` is **not** thread-safe. Concurrent calls to `Add`, `Save`, or other mutating methods must be synchronized externally.
- **`BaselineFile` lifecycle**: `BaselineFile` instances are obtained exclusively through `Load` or `FromJson`, or by direct instantiation for an empty baseline. There is no public constructor documented on `SecretFinding` for creating a `BaselineFile` directly, but the usage examples assume a parameterless constructor exists for the empty case.
- **JSON format**: The serialization format produced by `ToJson` and `Save` is an implementation detail of the baseline schema. Callers should not modify baseline files manually unless they fully understand the expected structure, as malformed files will cause `Load` and `FromJson` to throw.
