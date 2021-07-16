using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Test;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Mvc;

namespace OpenIdConnectServerMock.Controllers
{
    [Route("claims")]
    public class ClaimsController : Controller
    {
        private readonly IdentityServerTools _tools;
        private readonly ITokenValidator _tokenValidator;
        private readonly TestUserStore _userStore;

        public ClaimsController(IdentityServerTools tools, ITokenValidator tokenValidator, TestUserStore userStore)
        {
            _tools = tools;
            _tokenValidator = tokenValidator;
            _userStore = userStore;
        }

        [HttpGet("{claim}")]
        public async Task<IActionResult> GetClaim(string claim)
        {
            var subjectId = await ValidateBearerTokenAsync();
            if (string.IsNullOrEmpty(subjectId))
            {
                return Unauthorized();
            }

            var user = _userStore.FindBySubjectId(subjectId);
            if (subjectId is null)
            {
                return Unauthorized();
            }

            var claims = user.Claims.Where(c => c.Type == claim);

            var jwt = await _tools.IssueJwtAsync(300, claims);

            return Ok(jwt);
        }

        private async Task<string> ValidateBearerTokenAsync()
        {
            var token = GetToken();
            if (token is null)
            {
                return string.Empty;
            }

            var result = await _tokenValidator.ValidateAccessTokenAsync(token);
            if (result.IsError)
            {
                return string.Empty;
            }

            var subject = result.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            return subject;
        }

        private string GetToken()
        {
            if (Request.Headers.TryGetValue("Authorization", out var token)
                && token[0].StartsWith("Bearer "))
            {
                return token[0].Substring("Bearer ".Length);
            }

            return null;
        }

    }
}
