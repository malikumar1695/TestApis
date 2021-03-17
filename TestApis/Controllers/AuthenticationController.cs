using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TestApis.Database;
using TestApis.ViewModels;

namespace TestApis.Controllers
{
   // [Authorize]
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel registerViewModel)
        {
            var userExist = await userManager.FindByNameAsync(registerViewModel.UserName);
            if (userExist != null)
                return BadRequest("User is already exist");
            var AppUser = new ApplicationUser()
            {
                UserName = registerViewModel.UserName,
                Email = registerViewModel.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var result = await userManager.CreateAsync(AppUser, registerViewModel.Password);
            if (!result.Succeeded)
                return BadRequest("user creation failed");

            return Ok("User Successfully Created");
        }
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginViewModel loginViewModel)
        {
            var userExist = await userManager.FindByNameAsync(loginViewModel.UserName);
            if (userExist != null && await userManager.CheckPasswordAsync(userExist, loginViewModel.Password))
            {
                var userRoles = await userManager.GetRolesAsync(userExist);
                var authClaims = new List<Claim>{
                new Claim(ClaimTypes.Name , userExist.UserName),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };
                foreach(var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                var signKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("JWT:Key")));

                var token = new JwtSecurityToken(
                    issuer: configuration.GetValue<string>("JWT:ValidIssuer"),
                    audience: configuration.GetValue<string>("JWT:ValidAudience"),
                    expires: DateTime.Now.AddHours(5),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(signKey,SecurityAlgorithms.HmacSha256)
                    );
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }

            return Unauthorized();
        }
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok("Get Request Successful");
        }
    }
}
