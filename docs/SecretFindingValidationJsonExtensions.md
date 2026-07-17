# SecretFindingValidationJsonExtensions

Provides JSON serialization and deserialization helpers for `SecretFindingValidation` types, enabling easy conversion between validation results and their JSON representation for storage, transmission, or logging.

## API

### `public static string ToJson(this SecretFindingValidation validation)`
Serializes a single `SecretFindingValidation` instance to a JSON string.  
- **Parameters**  
  - `validation`: The validation result to serialize.  
- **Return value**  
  - A JSON‑encoded string representing the validation.  
- **Exceptions**  
  - Throws `ArgumentNullException` if `validation` is `null`.  
  - Throws `JsonSerializationException` if the object cannot be serialized.

### `public static string ToJson(this IEnumerable<SecretFindingValidation> validations)`
Serializes a collection of `SecretFindingValidation` instances to a JSON array string.  
- **Parameters**  
  - `validations`: The sequence of validation results to serialize.  
- **Return value**  
  - A JSON‑encoded array string.  
- **Exceptions**  
  - Throws `ArgumentNullException` if `validations` is `null`.  
  - Throws `JsonSerializationException` if any element cannot be serialized.

### `public static IReadOnlyList<string>? FromValidationJson(this string json)`
Deserializes a JSON string produced by `ToJson` into a read‑only list of validation messages (or `null` if the JSON represents an empty result).  
- **Parameters**  
  - `json`: The JSON string to deserialize.  
- **Return value**  
  - An `IReadOnlyList<string>` containing validation messages, or `null` when the JSON indicates no messages.  
- **Exceptions**  
  - Throws `ArgumentNullException` if `json` is `null`.  
  - Throws `JsonSerializationException` if the JSON is malformed or does not match the expected format.

### `public static bool TryFromValidationJson(this string json, [NotNullWhen(true)] out IReadOnlyList<string>? result)`
Attempts to deserialize a JSON string into a read‑only list of validation messages without throwing exceptions on failure.  
- **Parameters**  
  - `json`: The JSON string to attempt to parse.  
  - `result`: When the method returns `true`, contains the deserialized list; otherwise `null`.  
- **Return value**  
  - `true` if `json` was successfully parsed; `false` otherwise.  
- **Exceptions**  
  - None; all error conditions are reported via the return value.

### `public static bool? FromValidationResultJson(this string json)`
Deserializes a JSON string that represents a boolean validation outcome (true, false, or null) into a nullable `bool`.  
- **Parameters**  
  - `json`: The JSON string to deserialize.  
- **Return value**  
  - `true` if the JSON indicates a successful validation, `false` for a failure, or `null` when the JSON does not represent a definitive boolean outcome.  
- **Exceptions**  
  - Throws `ArgumentNullException` if `json` is `null`.  
  - Throws `JsonSerializationException` if the JSON cannot be interpreted as a nullable boolean.

### `public static bool TryFromValidationResultJson(this string json, [NotNullWhen(true)] out bool? result)`
Attempts to parse a JSON string into a nullable `bool` representing a validation outcome, returning `false` on failure instead of throwing.  
- **Parameters**  
  - `json`: The JSON string to attempt to parse.  
  - `result`: When the method returns `true`, contains the parsed nullable boolean; otherwise `null`.  
- **Return value**  
  - `true` if parsing succeeded; `false` if the input was invalid or could not be interpreted.  
- **Exceptions**  
  - None; parsing failures are indicated by the return value.

## Usage

```csharp
using DotNetSecretsScan.Validation;

// Assume we have a SecretFindingValidation instance obtained from scanning.
SecretFindingValidation validation = scanner.Validate(secret);

// Convert the validation result to JSON for logging or transmission.
string json = validation.ToJson();
// json now contains something like: {"IsValid":false,"Messages":["Pattern matched"]}

// Later, retrieve the validation messages from the JSON.
IReadOnlyList<string>? messages = json.FromValidationJson();
// messages contains ["Pattern matched"] or null if there were none.

// Safe parsing that does not throw on bad input.
if (json.TryFromValidationJson(out var safeMessages))
{
    // Use safeMessages; it is guaranteed to be non‑null when true is returned.
}
else
{
    // Handle malformed JSON gracefully.
}
```

```csharp
using System.Collections.Generic;
using DotNetSecretsScan.Validation;

// Serialize a batch of validations.
IEnumerable<SecretFindingValidation> batch = GetValidations();
string batchJson = batch.ToJson();
// batchJson is a JSON array: [{"IsValid":true},{"IsValid":false,"Messages":["..."}]]

// Deserialize a boolean outcome from a separate service call.
string outcomeJson = await Http.GetStringAsync("/api/validation/outcome");
bool? outcome = outcomeJson.FromValidationResultJson();
// outcome is true, false, or null depending on the service response.

// Try‑parse version for defensive coding.
if (outcomeJson.TryFromValidationResultJson(out bool? safeOutcome))
{
    // Proceed with safeOutcome (may be null).
}
else
{
    // Log or fallback when the JSON is not a valid boolean representation.
}
```

## Notes

- All extension methods are **static** and operate solely on their input parameters; they contain no mutable state and are therefore **thread‑safe**.  
- The `FromValidationJson` and `TryFromValidationJson` methods expect JSON produced by the corresponding `ToJson` overloads; feeding them arbitrary JSON may result in `null` or a failed parse (`false` return).  
- Null inputs`fully: passing a `null` returns `false`).  
- The nullable boolean helpers (`FromValidationResultJson` and `TryFromValidationResultJson`) treat the JSON literals `true`, `false`, and `null` as the respective `bool?` values; any other JSON token causes a parse failure.  
- If the input sequence to the collection `ToJson` overload is `null`, an `ArgumentNullException` is thrown immediately; empty sequences serialize to an empty JSON array (`[]`).  
- The methods do not perform any additional validation beyond JSON (de)serialization; callers should ensure that the underlying `SecretFindingValidation` objects are in a consistent state before serialization.
