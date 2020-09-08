using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CentralizedOAuth.Model;
using CentralizedOAuth.Processor;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CentralizedOAuth.Controllers
{
    [Route("connect")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        [HttpPost]
        [Route("token")]
        public ActionResult<AccessTokenResult> AccessToken([FromForm] string clientId, [FromForm] string apiKey)
        {
            try
            {
                var tokenCreation = new TokenCreation(clientId, apiKey);
                var tokenResult = tokenCreation.ValidateCredential();

                return this.Ok(tokenResult);
            }
            catch (Exception ex)
            {
                return this.StatusCode(500, ex.Message);
            }
        }

        [HttpPost]
        [Route("validate")]
        public ActionResult<ValidationResult> ValidateToken([FromQuery] string token)
        {
            try
            {
                var tokenValidation = new TokenValidation(token);
                var validationResult = tokenValidation.ValidateToken();

                return this.Ok(validationResult);
            }
            catch (Exception ex)
            {
                return this.StatusCode(500, ex.Message);
            }
        }

        [HttpGet]
        [Route("validate")]
        public ActionResult<ValidationResult> ValidateToken1([FromQuery] string token)
        {
            try
            {
                var tokenValidation = new TokenValidation(token);
                var validationResult = tokenValidation.ValidateToken();

                return this.Ok(validationResult);
            }
            catch (Exception ex)
            {
                return this.StatusCode(500, ex.Message);
            }
        }
    }
}
