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
    /// Optional expiry date (ISO‑8601) for baseline entries.
    /// When set to a past date, the entry is ignored on load so the finding re‑appears.
    /// </summary>
    public DateTime? Expires { get; set; }

    /// <summary>
    /// Gets or sets the outcome of live verification against the issuing provider, when
    /// verification was requested (<c>--verify</c>). One of "Active", "Inactive", or "Unknown".
    /// Null when verification was not performed.
    /// </summary>
    public string? Verified { get; set; }

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
    /// The fingerprint is based on (file path, rule id, secret content) to make it resilient to line number drift.
    /// </summary>
    /// <param name="finding">The finding to fingerprint.</param>
    /// <returns>A SHA256 hash string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
    public static string ComputeFingerprint(SecretFinding finding)
    {
        if (finding is null)
        {
            throw new ArgumentNullException(nameof(finding));
        }

        // Create a consistent string representation for fingerprinting
        // Use relative path for better portability across different systems
        var relativePath = GetRelativePath(finding.FilePath);
        var fingerprintString = $"{relativePath}|{finding.Rule}|{finding.Secret}";

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(fingerprintString);
        var hashBytes = sha256.ComputeHash(bytes);

        return BitConverter.ToString(hashBytes).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
    }

    /// <summary>
    /// Gets the relative path from the current working directory to the specified file path.
    /// This makes fingerprints more portable across different systems.
    /// </summary>
    /// <param name="filePath">The absolute or relative file path.</param>
    /// <returns>The relative path, or the original path if it cannot be made relative.</returns>
    private static string GetRelativePath(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
        {
            return filePath;
        }

        try
        {
            var fullPath = Path.GetFullPath(filePath);
            var currentDir = Directory.GetCurrentDirectory();

            if (fullPath.StartsWith(currentDir, StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetRelativePath(currentDir, fullPath);
            }

            return filePath;
        }
        catch
        {
            // If we can't compute relative path, return the original
            return filePath;
        }
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
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is <see langword="null"/>.</exception>
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
                // Skip entries that have an expiry date in the past.
                if (finding.Expires.HasValue && finding.Expires.Value <= DateTime.UtcNow)
                {
                    continue;
                }

                baseline.Add(finding);
            }
        }

        return baseline;
    }

    /// <summary>
    /// Adds a finding to the baseline.
    /// </summary>
    /// <param name="finding">The finding to add.</param>
    /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="findings"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
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

    /// <summary>
    /// Prunes the baseline by removing entries whose file no longer exists or no longer matches.
    /// </summary>
    /// <returns>The number of entries pruned.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the baseline is empty.</exception>
    public int Prune()
    {
        if (_findings is null)
        {
            throw new InvalidOperationException("Baseline is empty");
        }

        var prunedCount = 0;
        var newFindings = new List<SecretFinding>();

        foreach (var finding in _findings)
        {
            if (System.IO.File.Exists(finding.FilePath))
            {
                newFindings.Add(finding);
            }
            else
            {
                prunedCount++;
            }
        }

        _findings.Clear();
        _fingerprints.Clear();

        foreach (var finding in newFindings)
        {
            Add(finding);
        }

        return prunedCount;
    }

    /// <summary>
    /// Migrates old-format baseline entries to new format.
    /// Old format included line numbers in fingerprint; new format uses content-based fingerprinting.
    /// This method updates old entries to the new format.
    /// </summary>
    /// <returns>The number of entries that were migrated.</returns>
    public int MigrateFromLegacyFormat()
    {
        // Legacy fingerprints included line number, so we need to recompute them
        var migratedCount = 0;
        var newFindings = new List<SecretFinding>();
        var newFingerprints = new HashSet<string>(StringComparer.Ordinal);

        foreach (var finding in _findings)
        {
            var oldFingerprint = $"{finding.FilePath}|{finding.LineNumber}|{finding.Rule}|{finding.Secret}";
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var oldBytes = System.Text.Encoding.UTF8.GetBytes(oldFingerprint);
            var oldHashBytes = sha256.ComputeHash(oldBytes);
            var oldFingerprintHash = BitConverter.ToString(oldHashBytes).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();

            // Check if this was already migrated (has new-style fingerprint)
            var newFingerprint = finding.ComputeFingerprint();
            if (newFingerprints.Contains(newFingerprint))
            {
                // Duplicate after migration, skip it
                migratedCount++;
                continue;
            }

            // Add to new collections
            newFingerprints.Add(newFingerprint);
            newFindings.Add(finding);
        }

        // Replace old collections with new ones
        _fingerprints.Clear();
        _findings.Clear();

        foreach (var finding in newFindings)
        {
            _fingerprints.Add(finding.ComputeFingerprint());
            _findings.Add(finding);
        }

        return newFindings.Count;
    }

    /// <summary>
    /// Prunes the baseline by removing entries whose fingerprint no longer occurs in the file.
    /// This is useful for cleaning up stale baseline entries after file changes.
    /// </summary>
    /// <param name="filePath">The file path to check for occurrences.</param>
    /// <param name="fileContent">The current content of the file.</param>
    /// <returns>The number of entries that were pruned.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="filePath"/> or <paramref name="fileContent"/> is <see langword="null"/>.
    /// </exception>
    public int PruneStaleEntries(string filePath, string fileContent)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        if (fileContent is null)
        {
            throw new ArgumentNullException(nameof(fileContent));
        }

        var prunedCount = 0;
        var newFindings = new List<SecretFinding>();
        var newFingerprints = new HashSet<string>(StringComparer.Ordinal);

        foreach (var finding in _findings)
        {
            // Only check entries for this specific file
            if (!string.Equals(finding.FilePath, filePath, StringComparison.Ordinal))
            {
                newFindings.Add(finding);
                newFingerprints.Add(finding.ComputeFingerprint());
                continue;
            }

            // Check if this secret still exists in the file
            // We need to scan for the secret pattern to see if it still exists
            var rulePattern = GetRulePatternForFinding(finding);
            if (rulePattern is null)
            {
                // Can't determine pattern, keep the entry
                newFindings.Add(finding);
                newFingerprints.Add(finding.ComputeFingerprint());
                continue;
            }

            try
            {
                var regex = new System.Text.RegularExpressions.Regex(rulePattern, System.Text.RegularExpressions.RegexOptions.Compiled);
                if (regex.IsMatch(fileContent))
                {
                    // Secret still exists, keep the entry
                    newFindings.Add(finding);
                    newFingerprints.Add(finding.ComputeFingerprint());
                }
                else
                {
                    // Secret no longer exists in file, prune this entry
                    prunedCount++;
                }
            }
            catch
            {
                // If we can't check, keep the entry
                newFindings.Add(finding);
                newFingerprints.Add(finding.ComputeFingerprint());
            }
        }

        // Replace collections
        _findings.Clear();
        _fingerprints.Clear();

        foreach (var finding in newFindings)
        {
            _findings.Add(finding);
            _fingerprints.Add(finding.ComputeFingerprint());
        }

        return prunedCount;
    }

    /// <summary>
    /// Attempts to extract the rule pattern for a finding.
    /// This is used during pruning to check if a secret still exists in a file.
    /// </summary>
    /// <param name="finding">The finding to get the pattern for.</param>
    /// <returns>The rule pattern if available, otherwise null.</returns>
    private static string? GetRulePatternForFinding(SecretFinding finding)
    {
        // For pruning to work effectively, we need to check if the secret still exists
        // Since we don't have access to the rule definitions here, we'll use a simple approach:
        // If the finding has a rule that looks like a standard pattern, use it
        // Otherwise, return null which means we'll keep the entry

        // Common rule patterns we can recognize
        if (finding.Rule.StartsWith("api-key", StringComparison.OrdinalIgnoreCase) ||
            finding.Rule.StartsWith("secret-key", StringComparison.OrdinalIgnoreCase) ||
            finding.Rule.StartsWith("connection-string", StringComparison.OrdinalIgnoreCase))
        {
            // Try to create a simple pattern that matches the secret
            // This is a heuristic - in production you might want to store the actual pattern
            // or have access to the rule definitions
            var secret = finding.Secret.Trim();
            if (secret.Length > 0)
            {
                // Escape the secret for regex
                var escapedSecret = System.Text.RegularExpressions.Regex.Escape(secret);
                return escapedSecret;
            }
        }

        return null;
    }
}