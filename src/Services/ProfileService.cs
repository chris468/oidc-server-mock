using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace OpenIdConnectServer.Services
{
    internal class ProfileService : IProfileService
    {
        private const int MaximumInlineClaimCount = 5;

        private readonly TestUserStore _userStore;
        private readonly ILogger Logger;
        private readonly string _baseUri;

        public ProfileService(TestUserStore userStore, ILogger<ProfileService> logger, IHttpContextAccessor httpContextAccessor)
        {
            _userStore = userStore;
            Logger = logger;

            _baseUri = httpContextAccessor.HttpContext.GetIdentityServerBaseUrl() + "/claims/";
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            Logger.LogDebug("Getting profile data for subjectId: {subjectId}", subjectId);
            var user = this._userStore.FindBySubjectId(subjectId);
            if (user != null)
            {
                Logger.LogDebug("The user was found in store");
                IEnumerable<Claim> claims = context.FilterClaims(user.Claims);
                claims = SwapOutDistributedClaims(claims);
                context.AddRequestedClaims(claims);
            }
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            Logger.LogDebug("Checking if the user is active for subjectId: {subject}", subjectId);
            var user = this._userStore.FindBySubjectId(subjectId);
            context.IsActive = user?.IsActive ?? false;
            Logger.LogDebug("The user is active: {isActive}", context.IsActive);
            return Task.CompletedTask;
        }

        internal IEnumerable<Claim> SwapOutDistributedClaims(IEnumerable<Claim> claims)
        {
            var result = new List<Claim>();
            var claimNames = new Dictionary<string, string>();
            var claimSources = new Dictionary<string, Dictionary<string, string>>();
            var groupedClaims = claims.GroupBy(c => c.Type);
            foreach (var group in groupedClaims)
            {
                if (group.Count() > MaximumInlineClaimCount)
                {
                    claimNames[group.Key] = group.Key;
                    claimSources[group.Key] = new Dictionary<string, string>
                    {
                        ["endpoint"] = _baseUri + group.Key
                    };
                }
                else
                {
                    result.AddRange(group);
                }
            }

            if (claimNames.Any())
            {
                result.Add(new Claim("_claim_names", JsonConvert.SerializeObject(claimNames), IdentityServerConstants.ClaimValueTypes.Json));
                result.Add(new Claim("_claim_sources", JsonConvert.SerializeObject(claimSources), IdentityServerConstants.ClaimValueTypes.Json));
            }

            return result;
        }
    }
}
