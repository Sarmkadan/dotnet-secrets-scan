using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DotnetSecretsScan.Verification;

/// <summary>
/// Outcome of a live verification attempt against a credential's issuing provider.
/// </summary>
public enum VerificationStatus
{
    /// <summary>
    /// The provider confirmed the credential is still valid and usable.
    /// </summary>
    Active,

    /// <summary>
    /// The provider confirmed the credential has been revoked, rotated, or never existed.
    /// </summary>
    Inactive,

    /// <summary>
    /// Verification could not be completed (network failure, timeout, circuit open, or
    /// unsupported rule) so the credential's live status is unknown.
    /// </summary>
    Unknown
}

/// <summary>
/// Performs opt-in, best-effort live verification of leaked credentials by making a single
/// cheap, read-only API call against the issuing provider. Verification never throws: any
/// failure degrades the result to <see cref="VerificationStatus.Unknown"/> so a broken network
/// or a provider outage can never fail the scan.
/// </summary>
public sealed class SecretVerifier : IDisposable
{
    /// <summary>
    /// Maximum number of consecutive network-level failures (timeouts, connection errors, or
    /// 5xx responses that exhausted retries) tolerated for a single provider before the circuit
    /// breaker opens and further verifications for that provider short-circuit to
    /// <see cref="VerificationStatus.Unknown"/> without any additional network I/O.
    /// </summary>
    public const int CircuitBreakerThreshold = 3;

    /// <summary>
    /// Number of retry attempts performed after the initial request, for a total of up to
    /// three attempts per verification call.
    /// </summary>
    public const int MaxRetries = 2;

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan BaseBackoff = TimeSpan.FromMilliseconds(200);

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly ConcurrentDictionary<string, int> _consecutiveFailures = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretVerifier"/> class.
    /// </summary>
    /// <param name="httpClient">
    /// Optional <see cref="HttpClient"/> to use for verification calls. When omitted, an
    /// internal client with a 5 second timeout is created and owned by this instance.
    /// </param>
    public SecretVerifier(HttpClient? httpClient = null)
    {
        if (httpClient is null)
        {
            _httpClient = new HttpClient { Timeout = RequestTimeout };
            _ownsHttpClient = true;
        }
        else
        {
            _httpClient = httpClient;
            _ownsHttpClient = false;
        }
    }

    /// <summary>
    /// Resolves which provider owns the given rule id, if any of the providers eligible for
    /// live verification (AWS access keys, GitHub personal access tokens, Slack tokens).
    /// </summary>
    /// <param name="ruleId">The rule id that produced the finding.</param>
    /// <returns>The provider key ("aws", "github", "slack"), or null if the rule is not verifiable.</returns>
    /// <exception cref="ArgumentException"><paramref name="ruleId"/> is null or empty.</exception>
    public static string? ResolveProvider(string ruleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(ruleId);

        return ruleId switch
        {
            "SS001" or "SS002" => "aws",
            "SS006" or "SS007" or "SS019" => "github",
            "SS008" => "slack",
            _ => null
        };
    }

    /// <summary>
    /// Attempts to verify a single finding against its issuing provider's API.
    /// </summary>
    /// <param name="finding">The finding to verify.</param>
    /// <param name="cancellationToken">Token used to cancel the verification call.</param>
    /// <returns>
    /// <see cref="VerificationStatus.Active"/> or <see cref="VerificationStatus.Inactive"/> when
    /// the provider gave a conclusive answer, otherwise <see cref="VerificationStatus.Unknown"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="finding"/> is null.</exception>
    public async Task<VerificationStatus> VerifyAsync(SecretFinding finding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var provider = ResolveProvider(finding.Rule);
        if (provider is null)
        {
            return VerificationStatus.Unknown;
        }

        if (IsCircuitOpen(provider))
        {
            return VerificationStatus.Unknown;
        }

        try
        {
            return provider switch
            {
                "aws" => await VerifyAwsAsync(finding.Secret, provider, cancellationToken).ConfigureAwait(false),
                "github" => await VerifyGitHubAsync(finding.Secret, provider, cancellationToken).ConfigureAwait(false),
                "slack" => await VerifySlackAsync(finding.Secret, provider, cancellationToken).ConfigureAwait(false),
                _ => VerificationStatus.Unknown
            };
        }
        catch
        {
            // Verification must never throw; any unexpected failure degrades to Unknown.
            return VerificationStatus.Unknown;
        }
    }

    /// <summary>
    /// Verifies an AWS access key id. Sends an unsigned GetCallerIdentity request to STS: AWS
    /// validates the access key id against its account database before checking the request
    /// signature, so the error code alone tells us whether the key id exists without ever
    /// needing the paired secret access key.
    /// </summary>
    private async Task<VerificationStatus> VerifyAwsAsync(string accessKeyId, string provider, CancellationToken cancellationToken)
    {
        using var response = await SendWithRetryAsync(
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "https://sts.amazonaws.com/");
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "AWS4-HMAC-SHA256",
                    $"Credential={accessKeyId}/00000000/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000");
                request.Content = new StringContent("Action=GetCallerIdentity&Version=2011-06-15", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");
                return request;
            },
            provider,
            cancellationToken).ConfigureAwait(false);

        if (response is null)
        {
            return VerificationStatus.Unknown;
        }

        // 401/403 are conclusive answers, never retried, and must not trip the circuit breaker.
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return body.Contains("InvalidClientTokenId", StringComparison.OrdinalIgnoreCase)
            ? VerificationStatus.Inactive
            : body.Contains("SignatureDoesNotMatch", StringComparison.OrdinalIgnoreCase)
                ? VerificationStatus.Active
                : VerificationStatus.Unknown;
    }

    /// <summary>
    /// Verifies a GitHub personal access token by calling the authenticated-user endpoint.
    /// </summary>
    private async Task<VerificationStatus> VerifyGitHubAsync(string token, string provider, CancellationToken cancellationToken)
    {
        using var response = await SendWithRetryAsync(
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
                request.Headers.Authorization = new AuthenticationHeaderValue("token", token);
                request.Headers.UserAgent.ParseAdd("dotnet-secrets-scan");
                return request;
            },
            provider,
            cancellationToken).ConfigureAwait(false);

        if (response is null)
        {
            return VerificationStatus.Unknown;
        }

        return response.StatusCode switch
        {
            HttpStatusCode.OK => VerificationStatus.Active,
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => VerificationStatus.Inactive,
            _ => VerificationStatus.Unknown
        };
    }

    /// <summary>
    /// Verifies a Slack token by calling the read-only auth.test endpoint.
    /// </summary>
    private async Task<VerificationStatus> VerifySlackAsync(string token, string provider, CancellationToken cancellationToken)
    {
        using var response = await SendWithRetryAsync(
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "https://slack.com/api/auth.test");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return request;
            },
            provider,
            cancellationToken).ConfigureAwait(false);

        if (response is null)
        {
            return VerificationStatus.Unknown;
        }

        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            return VerificationStatus.Inactive;
        }

        if (!response.IsSuccessStatusCode)
        {
            return VerificationStatus.Unknown;
        }

        try
        {
            var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.TryGetProperty("ok", out var okProperty) && okProperty.ValueKind == JsonValueKind.True)
            {
                return VerificationStatus.Active;
            }

            if (document.RootElement.TryGetProperty("error", out var errorProperty))
            {
                var error = errorProperty.GetString();
                return error is "invalid_auth" or "account_inactive" or "token_revoked" or "token_expired"
                    ? VerificationStatus.Inactive
                    : VerificationStatus.Unknown;
            }

            return VerificationStatus.Unknown;
        }
        catch (JsonException)
        {
            return VerificationStatus.Unknown;
        }
    }

    /// <summary>
    /// Sends a request with up to <see cref="MaxRetries"/> retries using exponential backoff.
    /// Retries only occur for 5xx responses and network-level failures (timeouts, connection
    /// errors); 401/403 responses are conclusive and returned immediately without retrying,
    /// since "unauthorized" already answers the verification question. Every retried failure
    /// increments the provider's consecutive-failure counter for the circuit breaker; a
    /// conclusive response (including 401/403) resets it.
    /// </summary>
    private async Task<HttpResponseMessage?> SendWithRetryAsync(
        Func<HttpRequestMessage> requestFactory,
        string provider,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt <= MaxRetries; attempt++)
        {
            using var request = requestFactory();

            try
            {
                var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    RecordSuccess(provider);
                    return response;
                }

                if ((int)response.StatusCode >= 500 && attempt < MaxRetries)
                {
                    response.Dispose();
                    await DelayBeforeRetryAsync(attempt, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if ((int)response.StatusCode >= 500)
                {
                    RecordFailure(provider);
                    response.Dispose();
                    return null;
                }

                RecordSuccess(provider);
                return response;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException)
            {
                if (attempt < MaxRetries)
                {
                    await DelayBeforeRetryAsync(attempt, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                RecordFailure(provider);
                return null;
            }
        }

        return null;
    }

    private static Task DelayBeforeRetryAsync(int attempt, CancellationToken cancellationToken)
    {
        var backoff = TimeSpan.FromMilliseconds(BaseBackoff.TotalMilliseconds * Math.Pow(2, attempt));
        return Task.Delay(backoff, cancellationToken);
    }

    /// <summary>
    /// Reports whether the circuit breaker for the given provider is currently open, meaning
    /// verification for that provider has failed too many times in a row and should be skipped.
    /// </summary>
    /// <param name="provider">The provider key ("aws", "github", or "slack").</param>
    /// <returns>True if verification calls for this provider should be short-circuited.</returns>
    /// <exception cref="ArgumentException"><paramref name="provider"/> is null or empty.</exception>
    public bool IsCircuitOpen(string provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);

        return _consecutiveFailures.TryGetValue(provider, out var failures) && failures >= CircuitBreakerThreshold;
    }

    private void RecordFailure(string provider) =>
        _consecutiveFailures.AddOrUpdate(provider, 1, static (_, count) => count + 1);

    private void RecordSuccess(string provider) =>
        _consecutiveFailures.AddOrUpdate(provider, 0, static (_, _) => 0);

    /// <summary>
    /// Releases the internally owned <see cref="HttpClient"/>, if any.
    /// </summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
