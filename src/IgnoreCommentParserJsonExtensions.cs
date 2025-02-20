using System;
using System.Text.Json;

namespace DotnetSecretsScan;

/// <summary>
/// Configuration settings for the <see cref="IgnoreCommentParser"/>.
/// </summary>
public record IgnoreCommentSettings(
    bool Enabled = true,
    string[] IgnorePatterns = default!);

/// <summary>
/// Provides JSON serialization extensions for <see cref="IgnoreCommentSettings"/>.
/// </summary>
public static class IgnoreCommentParserJsonExtensions
{
    private static readonly JsonSerializerOptions Options = new()
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

        if (!indented)
        {
            return JsonSerializer.Serialize(value, Options);
        }

        var options = new JsonSerializerOptions(Options) { WriteIndented = true };
        return JsonSerializer.Serialize(value, options);
    }

    /// <summary>
    /// Deserializes a JSON string to an <see cref="IgnoreCommentSettings"/>.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>The deserialized <see cref="IgnoreCommentSettings"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is null or empty.</exception>
    /// <exception cref="JsonException">Thrown when the JSON is invalid.</exception>
    public static IgnoreCommentSettings? FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        return JsonSerializer.Deserialize<IgnoreCommentSettings>(json, Options);
    }

    /// <summary>
    /// Tries to deserialize a JSON string to an <see cref="IgnoreCommentSettings"/>.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <param name="value">The deserialized <see cref="IgnoreCommentSettings"/>, or null if deserialization failed.</param>
    /// <returns>True if deserialization was successful; otherwise, false.</returns>
    public static bool TryFromJson(string json, out IgnoreCommentSettings? value)
    {
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
