using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

public static class CloudProviderRules
{
    public static IReadOnlyList<SecretRule> All { get; } = new List<SecretRule>
    {
        new SecretRule(
            "AzureStorageAccountKey",
            "Azure Storage Account Key",
            @"[a-zA-Z0-9]{2,3}[_][a-zA-Z0-9]{2,3}[_][a-zA-Z0-9]{4,5}[_][a-zA-Z0-9]{2,3}[_][a-zA-Z0-9]{2,3}[_][a-zA-Z0-9]{2,3}=[a-zA-Z0-9+/=]{40,}",
            "Detects Azure Storage account keys",
            SecretSeverity.High),

        new SecretRule(
            "AzureSasToken",
            "Azure SAS Token",
            @"sv=[a-zA-Z0-9]+&st=[a-zA-Z0-9:]+&se=[a-zA-Z0-9:]+&sp=[a-zA-Z]+&spr=[a-zA-Z0-9]+&sig=[a-zA-Z0-9+/=]+",
            "Detects Azure SAS tokens",
            SecretSeverity.High),

        new SecretRule(
            "GcpServiceAccount",
            "GCP Service Account Key",
            @"""type"":\s*""service_account""\s*.*""private_key"":\s*""[a-zA-Z0-9+/=]+"".*",
            "Detects GCP service account keys",
            SecretSeverity.High),

        new SecretRule(
            "StripeLiveKey",
            "Stripe Live Key",
            @"sk_live_[a-zA-Z0-9]{24,}",
            "Detects Stripe live keys",
            SecretSeverity.High),

        new SecretRule(
            "StripeTestKey",
            "Stripe Test Key",
            @"sk_test_[a-zA-Z0-9]{24,}",
            "Detects Stripe test keys",
            SecretSeverity.Medium),

        new SecretRule(
            "SendGridApiKey",
            "SendGrid API Key",
            @"SG\.[a-zA-Z0-9]{10,}",
            "Detects SendGrid API keys",
            SecretSeverity.Medium),

        new SecretRule(
            "SlackToken",
            "Slack Token",
            @"xox[bpoas]-[a-zA-Z0-9]{10,}",
            "Detects Slack tokens",
            SecretSeverity.High),

        new SecretRule(
            "PemPrivateKey",
            "PEM Private Key",
            @"-----BEGIN.*PRIVATE KEY-----.*",
            "Detects PEM private keys",
            SecretSeverity.High),
    };
}
