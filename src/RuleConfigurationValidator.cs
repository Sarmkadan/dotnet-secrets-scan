using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Validates <see cref="RuleConfiguration"/> up front so that a broken rule set fails fast with a clear message
/// instead of silently skipping rules or scanning with an ambiguous rule set.
/// </summary>
/// <remarks>
/// <para>
/// Every violation is collected and returned together, so a user can fix all problems in one pass.
/// The known rule set is the built-in and cloud provider rules plus any custom rules in the configuration.
/// </para>
/// </remarks>
public static class RuleConfigurationValidator
{
    /// <summary>
    /// Validates the configuration and returns every violation found.
    /// </summary>
    /// <param name="configuration">The configuration to validate. <see langword="null"/> means the default rule set.</param>
    /// <param name="baseRules">
    /// The rules shipped with the tool. Defaults to <see cref="BuiltInRules.All"/> followed by <see cref="CloudProviderRules.All"/>.
    /// </param>
    /// <returns>A list of human-readable violations. The list is empty when the configuration is valid.</returns>
    public static IReadOnlyList<string> Validate(RuleConfiguration? configuration, IEnumerable<SecretRule>? baseRules = null)
    {
        var errors = new List<string>();

        var builtIn = (baseRules ?? BuiltInRules.All.Concat(CloudProviderRules.All)).ToList();
        var knownIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var duplicate in FindDuplicates(builtIn.Select(rule => rule.Id)))
        {
            errors.Add($"Built-in rule id '{duplicate}' is defined more than once.");
        }

        foreach (var rule in builtIn)
        {
            knownIds.Add(rule.Id);
        }

        var customRules = configuration?.CustomRules ?? Array.Empty<RuleDefinition>();
        var customIds = new List<string>();
        for (var index = 0; index < customRules.Count; index++)
        {
            ValidateCustomRule(customRules[index], index, knownIds, customIds, errors);
        }

        knownIds.UnionWith(customIds);

        var enabledIds = configuration?.EnabledRuleIds ?? Array.Empty<string>();
        var disabledIds = configuration?.DisabledRuleIds ?? Array.Empty<string>();

        foreach (var id in enabledIds.Where(id => !knownIds.Contains(id ?? string.Empty)))
        {
            errors.Add($"Enabled rule id '{id}' does not match any known rule.");
        }

        foreach (var id in disabledIds.Where(id => !knownIds.Contains(id ?? string.Empty)))
        {
            errors.Add($"Disabled rule id '{id}' does not match any known rule.");
        }

        var enabledSet = new HashSet<string>(enabledIds.Where(id => id is not null), StringComparer.Ordinal);
        foreach (var id in disabledIds.Where(id => id is not null && enabledSet.Contains(id)).Distinct(StringComparer.Ordinal))
        {
            errors.Add($"Rule id '{id}' is both enabled and disabled.");
        }

        return errors;
    }

    private static void ValidateCustomRule(
        RuleDefinition rule,
        int index,
        HashSet<string> knownIds,
        List<string> customIds,
        List<string> errors)
    {
        var label = string.IsNullOrWhiteSpace(rule.Id)
            ? $"Custom rule #{index + 1}"
            : $"Custom rule '{rule.Id}'";

        if (string.IsNullOrWhiteSpace(rule.Id))
        {
            errors.Add($"{label}: id must not be empty.");
        }
        else if (knownIds.Contains(rule.Id) || customIds.Contains(rule.Id, StringComparer.Ordinal))
        {
            errors.Add($"{label}: id is already used by another rule.");
        }
        else
        {
            customIds.Add(rule.Id);
        }

        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            errors.Add($"{label}: name must not be empty.");
        }

        if (rule.Description is null)
        {
            errors.Add($"{label}: description must not be null (empty string is allowed).");
        }

        if (string.IsNullOrWhiteSpace(rule.Pattern))
        {
            errors.Add($"{label}: pattern must not be empty.");
        }
        else if (!TryCompilePattern(rule.Pattern, out var error))
        {
            errors.Add($"{label}: pattern is not a valid regular expression: {error}");
        }

        if (!IsKnownSeverity(rule.Severity))
        {
            errors.Add(
                $"{label}: severity '{rule.Severity}' must be one of: {string.Join(", ", Enum.GetNames<SecretSeverity>())}.");
        }
    }

    private static bool TryCompilePattern(string pattern, out string? error)
    {
        try
        {
            // Compile without RegexOptions.Compiled: this is a check, not a hot path. The timeout is the same one
            // SecretRule uses at scan time, so a pattern that passes here cannot hang the scan on backtracking.
            _ = new Regex(pattern, RegexOptions.None, SecretRule.MatchTimeout);
            error = null;
            return true;
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool IsKnownSeverity(string? severity) =>
        severity is not null
        && Enum.GetNames<SecretSeverity>().Any(name => string.Equals(name, severity, StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> FindDuplicates(IEnumerable<string> ids) =>
        ids.GroupBy(id => id, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);
}
