using CentralizedOAuth.Extension;
using CentralizedOAuth.Model;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CentralizedOAuth.Processor
{
    public class TokenCreation : ITokenCreation
    {
        private const string DEFAULT_ISSUER = "https://www.testing.com";
        private const string DEFAULT_TOKEN_TYPE = "Bearer";
        private const string TEST_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAoT2r2y1s/BmiOSzW4mhax90NrPZY16D83ax74BxQS1r37Lw20ozK3ZoCWSnJ1vT0Fwd1wFRJ05xZku+dRPkYkWh9Kx+5+QAh7XCZM8e+8DXtxOomx7DZsBPrjw+MU0FpQltkz9Z/2YA3CDR3HQmc0F1YmTs7CQSNxD5vW1gyGgc4y306XKiWKT0B2rCxCNoZmNH2H/Y+5XlHTRVdn3yKTfJM2ga5fCQRbMxb+gP+aANF8S6SyDN1S3gW1ZtY9rXNkXmBZqWHFPJ2LmVQk+S74w+xUjpvAkPgx1o7hkQkf06wLlQRISZ1gbxcsfxYZyKTVVSHn6pPObT25aytqVLmpQIDAQABAoIBACfwyONQC1EfYGndS5Vl2CbuAPc5RqSTQk/+6+iF2vXvoL5JmSLqsU3XWoGPsmnG37fcpzRvLKJ4dk/JfyGYupc6VNcb0st1VvIkFC8ZaZjDIxTGE7kfe6z8Ijub1FzDNTm0vfIl5iGQexFTPbY5rViH5ux+GY+QSzWzaY4s+KwtfQ0KWRPNtPYXwwmtiCJAGfN3a5qitJNrMY4gSxoBa0azurkc4N8TXMKxsAHg1S+2oi6UUe52ylr3n/3wsb21RNvaknB1TFiLsHGuQMWyWxAcYky2105ZbtGCjQiFsrHqQqVtwJwWfWkAoul5idIPXtix7i4tJ0A3GZUTmH7mCXkCgYEA06R4rEEufZmt/M27tSc6pWwmLTEj40jeVTBhZEueLORbrw9qRblfBxQf2nioXQm7mltL9Nn0NiOuvuKN4spbNJ/hdFFQ8ReFRatAqpF+fnsD7jX/Ry6FOtupgOopVCHI8/RuYylwF9q3BUFN7JHgzMYsOBYGdVHgRU7LipRuqtsCgYEAwwjwdoul3BKXO8d311TUh8RRuZKY+ENCdtaACrNkKeBQ3Jp1L8uo8SVigUKE/g1SpbtQVQhBULnv9qCxsFscJEu1iQOsQD0SN1WnPkd7pIfglEIHLe1HihawBspcTPsjU1VMTlg8MVEj31a/13sp2t5/J5ONwGaUW5yp+4YzrH8CgYA1fOSujA6m2ZcaRBiDcPWmZw3C8B9kyr6+AusqQN4p9FCjjp7KHk5A6LogKcxLLzGFkjtBF3Bb2mrIfVNklMW2KA3/qqltNQeOkvhV4013w7k7k9P/dmdfd7KADS4CwEMcPJNFZmyY6sLEhjueZUPOHOuCBTb+oYGvonlYfaj2bwKBgEzs5LNNJ1EjAAVzCmCjM+SM2VMhcDZTiQ6IUh5mXTZrJFmujlQYtvzOKwkirIPry1JVDD1NsT1e6TfUb+FIPlROjD6LdVAtBldO8FUPKsRdV4YCeQRzV0ku46T6AefXEjrXJO6tvKgTAdwgQjCCgqKyKWL5vupJS3DK3Py5FP6PAoGBAM7d2P02e+oVGMKc/gHogEAcZBs+prLNfzbwHhyqA2N/GPKSR4CJYtheDOz/tK4FDP/vTWWAE2qAe8L3HUX9vttYrFvP0pJueF4c+Swp9i9/yQQY0k5pMaL0zPx0/ixLsBhm2GxEWXaZgFZzo77UH1USc33pxWUkuEjNV+RBGS8+-----END RSA PRIVATE KEY-----";
        private string clientId;
        private string apiKey;
        private ClientCredentials clientCredentials;
        private ApiKeyDetails apiKeyDetails;

        public TokenCreation(string clientId, string apiKey)
        {
            this.clientId = clientId;
            this.apiKey = apiKey;
            this.clientCredentials = new ClientCredentials();
            this.apiKeyDetails = new ApiKeyDetails();
        }

        public AccessTokenResult ValidateCredential()
        {
            //Validate and get client credentials in DB
            var clientCredentialDBResult = File.ReadAllText(@"C:\Projects\CentralizedOAuth\CentralizedOAuth\TestData\omddata.json");
            //var clientCredentialDBResult = File.ReadAllText(@"C:\Projects\CentralizedOAuth\CentralizedOAuth\TestData\apikeydata.json");

            this.clientCredentials = JsonConvert.DeserializeObject<ClientCredentials>(clientCredentialDBResult);

            this.apiKeyDetails = GetApiKeyDetails();

            return new AccessTokenResult
            {
                AccessToken = GenerateToken(),
                ExpiresIn = this.apiKeyDetails.AccessTokenExpiration,
                TokenType = DEFAULT_TOKEN_TYPE
            };
        }

        private string GenerateToken()
        {
            var signedAndEncodedToken = "";

            try
            {
                SecurityKey signingKey = RSASecurityKey(TEST_PRIVATE_KEY);
                SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

                var securityTokenDescriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = signingCredentials,
                    Audience = clientCredentials.ClientId,
                    Issuer = DEFAULT_ISSUER,
                    Expires = DateTime.Now.AddSeconds(apiKeyDetails.AccessTokenExpiration),
                    Claims = TokenClaims()
                };

                var tokenHandler = new JwtSecurityTokenHandler();

                //Signed the token
                var plainToken = tokenHandler.CreateToken(securityTokenDescriptor);

                //Build the token
                signedAndEncodedToken = tokenHandler.WriteToken(plainToken);
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return signedAndEncodedToken;
        }

        private RsaSecurityKey RSASecurityKey(string privateKey)
        {
            var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
            rsa.LoadPrivateKeyPEM(privateKey);
            return new RsaSecurityKey(rsa);
        }

        private Dictionary<string, object> TokenClaims()
        {
            return new Dictionary<string, object>()
            {
                {
                    "clientName", clientCredentials.ClientName
                },
                {
                    "globalId", apiKeyDetails.GlobalId
                },
                {
                    "requestor", apiKeyDetails.Requestor
                },
                {
                    "role", apiKeyDetails.Role
                },
                {
                    "rights",
                    apiKeyDetails.Rights
                }
            };
        }

        private ApiKeyDetails GetApiKeyDetails()
        {
            return this.clientCredentials.ApiKeys
                    .Where(key => key.ApiKey == this.apiKey)
                    .FirstOrDefault();
        }

        private long UnixTimeStamp()
        {
            return (Int64)(DateTimeOffset.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
        }
    }
}
