using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace DotnetSecretsScan.Tests;

public class RuleConfigurationValidatorTests
{
    private static RuleDefinition Custom(
        string? id = "SS100",
        string? pattern = "[a-z]{8}",
        string? severity = "High") =>
        new(id, "Custom rule", pattern, "Custom description", severity);

    [Fact]
    public void Validate_NullConfiguration_ReturnsNoErrors()
    {
        var errors = RuleConfigurationValidator.Validate(configuration: null);

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_ValidCustomRuleAndKnownIds_ReturnsNoErrors()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[] { Custom() },
            EnabledRuleIds: new[] { "SS100", "SS001" },
            DisabledRuleIds: new[] { "SS006" });

        var errors = RuleConfigurationValidator.Validate(configuration);

        Assert.Empty(errors);
    }

    [Fact]
    public void Validate_CustomRuleIdMatchesBuiltInRule_ReportsDuplicate()
    {
        var configuration = new RuleConfiguration(CustomRules: new[] { Custom(id: "SS001") });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains("'SS001'", error);
        Assert.Contains("already used by another rule", error);
    }

    [Fact]
    public void Validate_TwoCustomRulesShareId_ReportsDuplicate()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[] { Custom(id: "SS100"), Custom(id: "SS100", pattern: "other") });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains("'SS100'", error);
        Assert.Contains("already used by another rule", error);
    }

    [Fact]
    public void Validate_BaseRulesShareId_ReportsDuplicate()
    {
        var baseRules = new[]
        {
            new SecretRule("SS001", "First", "abc", "d", SecretSeverity.High),
            new SecretRule("SS001", "Second", "def", "d", SecretSeverity.High)
        };

        var error = Assert.Single(RuleConfigurationValidator.Validate(null, baseRules));
        Assert.Contains("Built-in rule id 'SS001' is defined more than once", error);
    }

    [Fact]
    public void Validate_BuiltInAndCloudProviderRules_HaveUniqueIds()
    {
        var errors = RuleConfigurationValidator.Validate(configuration: null);

        Assert.DoesNotContain(errors, error => error.Contains("defined more than once"));
    }

    [Theory]
    [InlineData("enabled")]
    [InlineData("disabled")]
    public void Validate_UnknownRuleId_ReportsReferenceInEitherList(string list)
    {
        var configuration = list == "enabled"
            ? new RuleConfiguration(EnabledRuleIds: new[] { "SS999" })
            : new RuleConfiguration(DisabledRuleIds: new[] { "SS999" });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains($"{char.ToUpperInvariant(list[0])}{list[1..]} rule id 'SS999' does not match any known rule", error);
    }

    [Fact]
    public void Validate_RuleIdFromCustomRule_IsKnown()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[] { Custom(id: "SS100") },
            DisabledRuleIds: new[] { "SS100" });

        Assert.Empty(RuleConfigurationValidator.Validate(configuration));
    }

    [Fact]
    public void Validate_RuleIdEnabledAndDisabled_ReportsConflict()
    {
        var configuration = new RuleConfiguration(
            EnabledRuleIds: new[] { "SS006" },
            DisabledRuleIds: new[] { "SS006" });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains("'SS006' is both enabled and disabled", error);
    }

    [Fact]
    public void Validate_PatternDoesNotCompile_ReportsRule()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[] { Custom(id: "SS100", pattern: "(unclosed") });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains("Custom rule 'SS100': pattern is not a valid regular expression", error);
    }

    [Theory]
    [InlineData("High")]
    [InlineData("medium")]
    [InlineData("LOW")]
    public void Validate_SeverityNameIgnoringCase_IsAccepted(string severity)
    {
        var configuration = new RuleConfiguration(CustomRules: new[] { Custom(severity: severity) });

        Assert.Empty(RuleConfigurationValidator.Validate(configuration));
    }

    [Theory]
    [InlineData("Critical")]
    [InlineData("5")]
    [InlineData("High, Low")]
    [InlineData(null)]
    public void Validate_SeverityOutsideAllowedSet_ReportsRule(string? severity)
    {
        var configuration = new RuleConfiguration(CustomRules: new[] { Custom(severity: severity) });

        var error = Assert.Single(RuleConfigurationValidator.Validate(configuration));
        Assert.Contains("Custom rule 'SS100': severity", error);
        Assert.Contains("must be one of: Low, Medium, High", error);
    }

    [Fact]
    public void Validate_MissingRequiredFields_ReportsEachField()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[] { new RuleDefinition(" ", null, "", null, "High") });

        var errors = RuleConfigurationValidator.Validate(configuration);

        Assert.Equal(4, errors.Count);
        Assert.Contains(errors, error => error.Contains("Custom rule #1: id must not be empty"));
        Assert.Contains(errors, error => error.Contains("Custom rule #1: name must not be empty"));
        Assert.Contains(errors, error => error.Contains("Custom rule #1: description must not be null"));
        Assert.Contains(errors, error => error.Contains("Custom rule #1: pattern must not be empty"));
    }

    [Fact]
    public void Validate_MultipleProblems_ReportsAllInOneList()
    {
        var configuration = new RuleConfiguration(
            CustomRules: new[]
            {
                Custom(id: "SS001"),
                Custom(id: "SS100", pattern: "(unclosed"),
                Custom(id: "SS101", severity: "Critical")
            },
            DisabledRuleIds: new[] { "SS999" });

        var errors = RuleConfigurationValidator.Validate(configuration);

        Assert.Equal(4, errors.Count);
        Assert.Single(errors, error => error.Contains("'SS001'") && error.Contains("already used"));
        Assert.Single(errors, error => error.Contains("'SS100'") && error.Contains("regular expression"));
        Assert.Single(errors, error => error.Contains("'SS101'") && error.Contains("severity"));
        Assert.Single(errors, error => error.Contains("'SS999'") && error.Contains("does not match any known rule"));
    }

    [Fact]
    public void Validate_ReportsBuiltInDuplicateAlongsideCustomProblems()
    {
        var baseRules = new List<SecretRule>
        {
            new("SS001", "First", "abc", "d", SecretSeverity.High),
            new("SS001", "Second", "def", "d", SecretSeverity.High)
        };
        var configuration = new RuleConfiguration(CustomRules: new[] { Custom(pattern: "(unclosed") });

        var errors = RuleConfigurationValidator.Validate(configuration, baseRules);

        Assert.Equal(2, errors.Count);
        Assert.Contains(errors, error => error.Contains("Built-in rule id 'SS001'"));
        Assert.Contains(errors, error => error.Contains("regular expression"));
    }
}
