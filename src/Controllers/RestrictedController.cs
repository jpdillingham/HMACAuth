using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace HMACAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class RestrictedController : ControllerBase
    {
        private readonly ILogger<RestrictedController> _logger;

        public RestrictedController(ILogger<RestrictedController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        [Route("")]
        [Authorize(Roles = "ApiKeyHolder")]
        public IActionResult Post([FromBody]string body)
        {
            _logger.LogInformation($"Successful POST of '{body}' from {Request.HttpContext.Connection.RemoteIpAddress}");
            Console.WriteLine(body);
            return Ok();
        }
    }
}
