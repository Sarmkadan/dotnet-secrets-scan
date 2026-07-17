using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace DotnetSecretsScan;

/// <summary>
/// Provides System.Text.Json serialization extensions for <see cref="SecretFinding"/>.
/// </summary>
public static class SecretFindingJsonExtensions
{
	private static readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		WriteIndented = false,
	};

	/// <summary>
	/// Serializes a <see cref="SecretFinding"/> to a JSON string.
	/// </summary>
	/// <param name="value">The secret finding to serialize.</param>
	/// <param name="indented">Whether to format the JSON with indentation for readability.</param>
	/// <returns>A JSON string representation of the secret finding.</returns>
	/// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
	public static string ToJson(this SecretFinding value, bool indented = false)
	{
		ArgumentNullException.ThrowIfNull(value);

		var options = indented
			? new JsonSerializerOptions(_jsonOptions) { WriteIndented = true }
			: _jsonOptions;

		return JsonSerializer.Serialize(value, options);
	}

	/// <summary>
	/// Deserializes a <see cref="SecretFinding"/> from a JSON string.
	/// </summary>
	/// <param name="json">The JSON string to deserialize.</param>
	/// <returns>The deserialized <see cref="SecretFinding"/> instance, or null if the JSON is empty or whitespace.</returns>
	/// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null.</exception>
	/// <exception cref="JsonException">Thrown when the JSON is invalid or cannot be deserialized to a <see cref="SecretFinding"/>.</exception>
	public static SecretFinding? FromJson(string json)
	{
		ArgumentNullException.ThrowIfNull(json);

		return string.IsNullOrWhiteSpace(json)
			? null
			: JsonSerializer.Deserialize<SecretFinding>(json, _jsonOptions);
	}

	/// <summary>
	/// Attempts to deserialize a <see cref="SecretFinding"/> from a JSON string.
	/// </summary>
	/// <param name="json">The JSON string to deserialize.</param>
	/// <param name="value">Receives the deserialized <see cref="SecretFinding"/> if successful; otherwise, null.</param>
	/// <returns>True if deserialization succeeded; otherwise, false.</returns>
	/// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null.</exception>
	public static bool TryFromJson(string json, [NotNullWhen(true)] out SecretFinding? value)
	{
		ArgumentNullException.ThrowIfNull(json);

		try
		{
			value = JsonSerializer.Deserialize<SecretFinding>(json, _jsonOptions);
			return value is not null;
		}
		catch (JsonException)
		{
			value = null;
			return false;
		}
	}
}