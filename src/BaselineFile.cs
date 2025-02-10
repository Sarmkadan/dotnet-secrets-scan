namespace DotnetSecretsScan;

/// <summary>
/// Represents a secret finding with location and rule information.
/// </summary>
public sealed class SecretFinding : IEquatable<SecretFinding>
{
    /// <summary>
    /// Gets or sets the file path where the secret was found.
    /// </summary>
    public required string FilePath { get; set; }

    /// <summary>
    /// Gets or sets the line number where the secret was found (1-indexed).
    /// </summary>
    public required int LineNumber { get; set; }

    /// <summary>
    /// Gets or sets the rule that matched the secret.
    /// </summary>
    public required string Rule { get; set; }

    /// <summary>
    /// Gets or sets the detected secret value.
    /// </summary>
    public required string Secret { get; set; }

    /// <summary>
    /// Gets or sets the severity level of the finding.
    /// </summary>
    public required string Severity { get; set; }

    /// <summary>
    /// Computes a fingerprint for the finding based on its identifying properties.
    /// </summary>
    /// <returns>A SHA256 hash string representing the finding.</returns>
    public string ComputeFingerprint()
    {
        return ComputeFingerprint(this);
    }

    /// <summary>
    /// Computes a fingerprint for a secret finding.
    /// </summary>
    /// <param name="finding">The finding to fingerprint.</param>
    /// <returns>A SHA256 hash string.</returns>
    public static string ComputeFingerprint(SecretFinding finding)
    {
        if (finding is null)
        {
            throw new ArgumentNullException(nameof(finding));
        }

        // Create a consistent string representation for fingerprinting
        var fingerprintString = $"{finding.FilePath}|{finding.LineNumber}|{finding.Rule}|{finding.Secret}";

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(fingerprintString);
        var hashBytes = sha256.ComputeHash(bytes);

        return BitConverter.ToString(hashBytes).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    public bool Equals(SecretFinding? other)
    {
        if (other is null)
        {
            return false;
        }

        return FilePath == other.FilePath
            && LineNumber == other.LineNumber
            && Rule == other.Rule
            && Secret == other.Secret;
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    public override bool Equals(object? obj) => Equals(obj as SecretFinding);

    /// <summary>
    /// Returns the hash code for this instance.
    /// </summary>
    public override int GetHashCode()
    {
        return HashCode.Combine(FilePath, LineNumber, Rule, Secret);
    }
}

/// <summary>
/// Manages a baseline of known/accepted secret findings.
/// </summary>
public sealed class BaselineFile
{
    private readonly HashSet<string> _fingerprints = new(StringComparer.Ordinal);
    private readonly List<SecretFinding> _findings = new();

    /// <summary>
    /// Gets the list of findings in the baseline.
    /// </summary>
    public IReadOnlyList<SecretFinding> Findings => _findings.AsReadOnly();

    /// <summary>
    /// Loads a baseline from a JSON file.
    /// If the file does not exist, returns an empty baseline.
    /// </summary>
    /// <param name="path">Path to the JSON baseline file.</param>
    /// <returns>A new BaselineFile instance.</returns>
    public static BaselineFile Load(string path)
    {
        if (path is null)
        {
            throw new ArgumentNullException(nameof(path));
        }

        if (!System.IO.File.Exists(path))
        {
            return new BaselineFile();
        }

        var json = System.IO.File.ReadAllText(path);
        return FromJson(json);
    }

    /// <summary>
    /// Deserializes a baseline from JSON.
    /// </summary>
    /// <param name="json">JSON string containing the baseline.</param>
    /// <returns>A new BaselineFile instance.</returns>
    public static BaselineFile FromJson(string json)
    {
        if (json is null)
        {
            throw new ArgumentNullException(nameof(json));
        }

        var baseline = new BaselineFile();
        var findings = System.Text.Json.JsonSerializer.Deserialize<List<SecretFinding>>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });

        if (findings is not null)
        {
            foreach (var finding in findings)
            {
                baseline.Add(finding);
            }
        }

        return baseline;
    }

    /// <summary>
    /// Adds a finding to the baseline.
    /// </summary>
    /// <param name="finding">The finding to add.</param>
    public void Add(SecretFinding finding)
    {
        if (finding is null)
        {
            throw new ArgumentNullException(nameof(finding));
        }

        var fingerprint = finding.ComputeFingerprint();
        if (_fingerprints.Add(fingerprint))
        {
            _findings.Add(finding);
        }
    }

    /// <summary>
    /// Checks if the baseline contains a specific finding.
    /// Comparison is based on the finding's fingerprint (file+rule+secret).
    /// </summary>
    /// <param name="finding">The finding to check.</param>
    /// <returns>True if the finding exists in the baseline; otherwise, false.</returns>
    public bool Contains(SecretFinding finding)
    {
        if (finding is null)
        {
            throw new ArgumentNullException(nameof(finding));
        }

        var fingerprint = finding.ComputeFingerprint();
        return _fingerprints.Contains(fingerprint);
    }

    /// <summary>
    /// Filters a collection of findings, returning only those not in the baseline.
    /// </summary>
    /// <param name="findings">Findings to filter.</param>
    /// <returns>Findings that are new (not in baseline).</returns>
    public IReadOnlyList<SecretFinding> FilterNew(IEnumerable<SecretFinding> findings)
    {
        if (findings is null)
        {
            throw new ArgumentNullException(nameof(findings));
        }

        var result = new List<SecretFinding>();
        foreach (var finding in findings)
        {
            if (finding is null)
            {
                continue;
            }

            if (!Contains(finding))
            {
                result.Add(finding);
            }
        }

        return result.AsReadOnly();
    }

    /// <summary>
    /// Saves the baseline to a JSON file.
    /// </summary>
    /// <param name="path">Path to save the JSON file.</param>
    public void Save(string path)
    {
        if (path is null)
        {
            throw new ArgumentNullException(nameof(path));
        }

        var json = System.Text.Json.JsonSerializer.Serialize(_findings, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        });

        System.IO.File.WriteAllText(path, json);
    }

    /// <summary>
    /// Converts the baseline to JSON.
    /// </summary>
    /// <returns>JSON representation of the baseline.</returns>
    public string ToJson()
    {
        return System.Text.Json.JsonSerializer.Serialize(_findings, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        });
    }
}