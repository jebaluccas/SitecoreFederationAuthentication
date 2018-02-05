using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Globalization;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Sitecore9.Lib
{
    public class AzureAdIdentityProviderProcessor : IdentityProvidersProcessor
    {

        public AzureAdIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }


        protected override string IdentityProviderName
        {
            get
            {
                return "AzureAd";
            }
        }
        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            IdentityProvider identityProvider =  this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();
            string authority = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}", "XXXXXX.onmicrosoft.com");
            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType=authenticationType,
                ClientId = "XXXXXXX",
                Authority = authority,
                PostLogoutRedirectUri = "http://sitecore9/sitecore/login",
                RedirectUri= "http://sitecore9/sitecore/login",
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = (context) =>
                    {
                        ClaimsIdentity identity = context.AuthenticationTicket.Identity;

                        foreach (Transformation current in identityProvider.Transformations)
                        {
                            current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }
                        return Task.FromResult(0);
                    }
                }

            });

        }
    }
}
