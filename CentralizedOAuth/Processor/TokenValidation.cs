using CentralizedOAuth.Extension;
using CentralizedOAuth.Model;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace CentralizedOAuth.Processor
{
    public class TokenValidation
    {
        private const string VALID_ISSUER = "https://www.testing.com";
        private const string TEST_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoT2r2y1s/BmiOSzW4mhax90NrPZY16D83ax74BxQS1r37Lw20ozK3ZoCWSnJ1vT0Fwd1wFRJ05xZku+dRPkYkWh9Kx+5+QAh7XCZM8e+8DXtxOomx7DZsBPrjw+MU0FpQltkz9Z/2YA3CDR3HQmc0F1YmTs7CQSNxD5vW1gyGgc4y306XKiWKT0B2rCxCNoZmNH2H/Y+5XlHTRVdn3yKTfJM2ga5fCQRbMxb+gP+aANF8S6SyDN1S3gW1ZtY9rXNkXmBZqWHFPJ2LmVQk+S74w+xUjpvAkPgx1o7hkQkf06wLlQRISZ1gbxcsfxYZyKTVVSHn6pPObT25aytqVLmpQIDAQAB-----END PUBLIC KEY-----";
        private const string TEST_WRONG_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06pYm1ahzazvS17zSZtQnqeE/fjJBcDNqVeD/kMqctBExND22PMoU9v1kmEvunhShIHPA3blgpLoOaQQD2+BiCwMZjCbAMEIwEl//sYvnICDUv4+UCMn6obwyhGEAldOwMxeVdocDdnAsvIaYflmSaec/ZP11EjZ+zujgimoO+7DxjZ652hTCPd9Mc7Z0i+lCM5MLK1PpNfYmUcwgI9yrOMQapCKKrURM/6XwEMP5gtLN7IXRUkZvI3zrCpD95Dr//x7s/jinylEWLoo7WKk6/eq9eXQOnCS47OMt/Mey4x3nSbZsCTvL2q3/xyselFZyRlfoc8eIqdd6cv6cQe0aQIDAQAB-----END PUBLIC KEY-----";
        private string token;
        
        public TokenValidation(string token)
        {
            this.token = token;
        }

        public ValidationResult ValidateToken() 
        {
            var validationResult = new ValidationResult();

            try
            {
                //Validate token
                var validateToken = Validate();

                if (validateToken != null)
                {
                    validationResult.Valid = true;
                    validationResult.Message = validateToken.ToString();
                }
                else
                {
                    validationResult.Valid = false;
                    validationResult.Message = "INVALID JWT";
                }
            }
            catch (Exception ex)
            {
                validationResult.Valid = false;
                validationResult.Message = ex.Message;
            }

            return validationResult;
        }

        private JwtSecurityToken Validate()
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                SecurityKey signingKey = RSASecurityKey(TEST_PUBLIC_KEY);
                SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

                var tokenValidationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = VALID_ISSUER,
                    IssuerSigningKey = signingKey,
                    ClockSkew = TimeSpan.Zero
                };

                SecurityToken validatedToken;

                tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);

                return (JwtSecurityToken)validatedToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private RsaSecurityKey RSASecurityKey(string publicKey)
        {
            var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
            rsa.LoadPublicKeyPEM(publicKey);
            return new RsaSecurityKey(rsa);
        }
    }
}
