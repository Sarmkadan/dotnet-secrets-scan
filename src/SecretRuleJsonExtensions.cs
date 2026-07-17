using System;
using System.Text.Json;

namespace DotnetSecretsScan;

/// <summary>
/// Provides JSON serialization extensions for <see cref="SecretRule"/>.
/// </summary>
public static class SecretRuleJsonExtensions
{
	private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		WriteIndented = false
	};

	/// <summary>
	/// Serializes a <see cref="SecretRule"/> to a JSON string.
	/// </summary>
	/// <param name="value">The <see cref="SecretRule"/> to serialize.</param>
	/// <param name="indented">Whether to format the JSON with indentation.</param>
	/// <returns>A JSON string representation of the <see cref="SecretRule"/>.</returns>
	/// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
	public static string ToJson(this SecretRule value, bool indented = false)
	{
		ArgumentNullException.ThrowIfNull(value);
		return !indented
			? JsonSerializer.Serialize(value, Options)
			: JsonSerializer.Serialize(value, new JsonSerializerOptions(Options) { WriteIndented = true });
	}

	/// <summary>
	/// Deserializes a JSON string to a <see cref="SecretRule"/>.
	/// </summary>
	/// <param name="json">The JSON string to deserialize.</param>
	/// <returns>The deserialized <see cref="SecretRule"/>, or <c>null</c> if the JSON represents a null value.</returns>
	/// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is null or empty.</exception>
	/// <exception cref="JsonException">Thrown when the JSON is invalid or cannot be deserialized to a <see cref="SecretRule"/>.</exception>
	public static SecretRule? FromJson(string json)
	{
		ArgumentException.ThrowIfNullOrEmpty(json);
		return JsonSerializer.Deserialize<SecretRule>(json, Options);
	}

	/// <summary>
	/// Tries to deserialize a JSON string to a <see cref="SecretRule"/>.
	/// </summary>
	/// <param name="json">The JSON string to deserialize.</param>
	/// <param name="value">The deserialized <see cref="SecretRule"/>, or <c>null</c> if deserialization failed.</param>
	/// <returns><c>true</c> if deserialization was successful; otherwise, <c>false</c>.</returns>
	public static bool TryFromJson(string json, out SecretRule? value)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			value = null;
			return false;
		}

		try
		{
			value = JsonSerializer.Deserialize<SecretRule>(json, Options);
			return true;
		}
		catch (JsonException)
		{
			value = null;
			return false;
		}
	}
}
