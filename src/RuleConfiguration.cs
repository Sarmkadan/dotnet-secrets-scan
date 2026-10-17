using System.Collections.Generic;

namespace DotnetSecretsScan;

/// <summary>
/// Rule set customization for a scan run. Checked by <see cref="RuleConfigurationValidator"/> before any file is enumerated.
/// </summary>
/// <param name="CustomRules">Additional rules to run alongside the built-in and cloud provider rules.</param>
/// <param name="EnabledRuleIds">Rule ids to enable. Each id must refer to an existing rule.</param>
/// <param name="DisabledRuleIds">Rule ids to disable. Each id must refer to an existing rule.</param>
public sealed record RuleConfiguration(
    IReadOnlyList<RuleDefinition>? CustomRules = null,
    IReadOnlyList<string>? EnabledRuleIds = null,
    IReadOnlyList<string>? DisabledRuleIds = null);
