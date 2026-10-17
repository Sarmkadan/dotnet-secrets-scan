using System;
using System.Text;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Translates the glob syntax accepted by <c>--exclude</c> into an anchored, case-insensitive regular expression.
/// </summary>
/// <remarks>
/// Supported syntax: <c>*</c> (any run of characters except <c>/</c>), <c>?</c> (one character except <c>/</c>),
/// <c>**/</c> (zero or more leading directories), a trailing <c>/**</c> (everything below a directory),
/// and <c>[...]</c> character classes with optional <c>!</c> negation. Backslashes are treated as <c>/</c>
/// so Windows-style patterns work. Brace alternatives such as <c>{a,b}</c> are rejected rather than
/// silently treated as literals.
/// </remarks>
public static class GlobPattern
{
    /// <summary>
    /// Normalizes a raw glob: trims whitespace, converts backslashes to forward slashes and drops trailing separators.
    /// </summary>
    /// <param name="glob">The raw glob text.</param>
    /// <returns>The normalized glob, which may be empty.</returns>
    public static string Normalize(string glob) =>
        glob.Trim().Replace('\\', '/').TrimEnd('/');

    /// <summary>
    /// Compiles a glob into a regular expression.
    /// </summary>
    /// <param name="glob">The glob to compile.</param>
    /// <returns>A case-insensitive regular expression that must match a whole path segment or path prefix.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="glob"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="glob"/> is not a valid glob.</exception>
    public static Regex Compile(string glob)
    {
        ArgumentNullException.ThrowIfNull(glob);

        if (!TryCompile(glob, out var regex, out var error))
        {
            throw new ArgumentException($"Invalid glob '{glob}': {error}", nameof(glob));
        }

        return regex!;
    }

    /// <summary>
    /// Attempts to compile a glob into a regular expression and reports why it failed.
    /// </summary>
    /// <param name="glob">The glob to compile.</param>
    /// <param name="regex">When this method returns <see langword="true"/>, the compiled expression; otherwise <see langword="null"/>.</param>
    /// <param name="error">When this method returns <see langword="false"/>, a short description of the problem; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the glob is valid; otherwise <see langword="false"/>.</returns>
    public static bool TryCompile(string glob, out Regex? regex, out string? error)
    {
        regex = null;
        error = null;

        if (glob is null)
        {
            error = "pattern is null";
            return false;
        }

        var normalized = Normalize(glob);
        if (normalized.Length == 0)
        {
            error = "pattern is empty";
            return false;
        }

        var builder = new StringBuilder("^");
        for (var i = 0; i < normalized.Length; i++)
        {
            var c = normalized[i];
            switch (c)
            {
                case '*' when i + 1 < normalized.Length && normalized[i + 1] == '*':
                    if (i + 2 < normalized.Length && normalized[i + 2] == '/')
                    {
                        builder.Append("(?:.*/)?");
                        i += 2;
                    }
                    else
                    {
                        builder.Append(".*");
                        i += 1;
                    }
                    break;

                case '/' when normalized.Length - i == 3 && normalized.EndsWith("/**", StringComparison.Ordinal):
                    builder.Append("(?:/.*)?");
                    i = normalized.Length;
                    break;

                case '*':
                    builder.Append("[^/]*");
                    break;

                case '?':
                    builder.Append("[^/]");
                    break;

                case '/':
                    builder.Append('/');
                    break;

                case '[':
                    var close = normalized.IndexOf(']', i + 1);
                    if (close < 0)
                    {
                        error = "unclosed '[' character class";
                        return false;
                    }

                    var body = normalized.Substring(i + 1, close - i - 1);
                    var negated = body.StartsWith('!');
                    if (negated)
                    {
                        body = body.Substring(1);
                    }

                    if (body.Length == 0)
                    {
                        error = "empty character class";
                        return false;
                    }

                    builder.Append('[');
                    if (negated)
                    {
                        builder.Append('^');
                    }

                    foreach (var classChar in body)
                    {
                        if (classChar is '[' or ']' or '^' or '\\')
                        {
                            builder.Append('\\');
                        }

                        builder.Append(classChar);
                    }

                    builder.Append(']');
                    i = close;
                    break;

                case '{':
                case '}':
                    error = "brace alternatives are not supported; pass one pattern per alternative";
                    return false;

                default:
                    builder.Append(Regex.Escape(c.ToString()));
                    break;
            }
        }

        builder.Append(@"\z");

        try
        {
            regex = new Regex(builder.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return true;
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
