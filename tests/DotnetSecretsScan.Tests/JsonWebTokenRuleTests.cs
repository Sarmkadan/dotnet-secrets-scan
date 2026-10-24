using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace DotnetSecretsScan.Tests;

public class JsonWebTokenRuleTests
{
    private static readonly Regex JwtRegex =
        BuiltInRules.All.Single(rule => rule.Id == "JWT001").Regex;

    [Theory]
    [InlineData("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")]
    [InlineData("token = \"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJleGFtcGxlIn0.dGhpcyBpcyBhIHRlc3Qgc2lnbmF0dXJl\"")]
    [InlineData("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEyMyJ9.-_-_-_-_-_-_-_-_")]
    public void Rule_PositiveSample_MatchesJwt(string sample)
    {
        Assert.Matches(JwtRegex, sample);
    }

    [Theory]
    [InlineData("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0")]
    [InlineData("abcdefghij.klmnopqrst.uvwxyzABCD")]
    [InlineData("eyJhbGciOi+IUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlMTIz")]
    [InlineData("eyJhbGciOiJIUzI1NiJ9.eyJz")]
    [InlineData("This is a plain sentence with no token in it.")]
    public void Rule_NegativeSample_DoesNotMatchJwt(string sample)
    {
        Assert.DoesNotMatch(JwtRegex, sample);
    }
}
