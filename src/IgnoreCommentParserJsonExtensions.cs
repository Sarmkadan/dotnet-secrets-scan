using System;
using System.Text.Json;

namespace DotnetSecretsScan;

/// <summary>
/// Configuration settings for the <see cref="IgnoreCommentParser"/>.
/// </summary>
public sealed record IgnoreCommentSettings(
    bool Enabled = true,
    string[]? IgnorePatterns = default);

/// <summary>
/// Provides JSON serialization extensions for <see cref="IgnoreCommentSettings"/>.
/// </summary>
public static class IgnoreCommentParserJsonExtensions
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    /// <summary>
    /// Serializes an <see cref="IgnoreCommentSettings"/> to a JSON string.
    /// </summary>
    /// <param name="value">The <see cref="IgnoreCommentSettings"/> to serialize.</param>
    /// <param name="indented">Whether to format the JSON with indentation.</param>
    /// <returns>A JSON string representation of the <see cref="IgnoreCommentSettings"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public static string ToJson(this IgnoreCommentSettings value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        return !indented
            ? JsonSerializer.Serialize(value, Options)
            : JsonSerializer.Serialize(value, new JsonSerializerOptions(Options) { WriteIndented = true });
    }

    /// <summary>
    /// Deserializes a JSON string to an <see cref="IgnoreCommentSettings"/>.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>The deserialized <see cref="IgnoreCommentSettings"/>, or <see langword="null"/> if the JSON represents a null value.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is <see langword="null"/>, empty, or consists only of white-space characters.</exception>
    /// <exception cref="JsonException">Thrown when the JSON is invalid or cannot be deserialized to <see cref="IgnoreCommentSettings"/>.</exception>
    public static IgnoreCommentSettings? FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        return JsonSerializer.Deserialize<IgnoreCommentSettings>(json, Options);
    }

    /// <summary>
    /// Tries to deserialize a JSON string to an <see cref="IgnoreCommentSettings"/>.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <param name="value">When this method returns, contains the deserialized <see cref="IgnoreCommentSettings"/> if deserialization was successful, or <see langword="null"/> if deserialization failed.</param>
    /// <returns><see langword="true"/> if deserialization was successful; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is <see langword="null"/>, empty, or consists only of white-space characters.</exception>
    public static bool TryFromJson(string json, out IgnoreCommentSettings? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);

        if (string.IsNullOrWhiteSpace(json))
        {
            value = null;
            return false;
        }

        try
        {
            value = JsonSerializer.Deserialize<IgnoreCommentSettings>(json, Options);
            return true;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
