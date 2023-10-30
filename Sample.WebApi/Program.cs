using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using SampleAngular.Configuration;
using SampleAngular.Models;
using System.Text; 
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.OpenApi.Models;


var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
//// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<App_BlazorDBContext>(options => options.UseSqlServer(connectionString));
builder.Services.AddScoped<JwtSecurityTokenHandler>();
builder.Services.AddDefaultIdentity<UserPofile>().AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<App_BlazorDBContext>();
//Register AutoMapper Service
builder.Services.AddAutoMapper(typeof(AutoMapperConfiguration));
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
//Authentiacate Jwt Token
builder.Services.AddAuthentication(option =>
{
    //When authenticate make sure you are using
    //beer scheme, mean anybody who is attempting
    //to access anything that we are secured
    //must provide jwt bearer
    option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    //    Mean you are going to challenge according
    //to the JWT bearer
    option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;



})
    .AddJwtBearer(option =>
    {
        option.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateAudience = true,
            ValidateIssuer = true,  //ensure that issuer is valid issuer
            ValidateLifetime = true,//ensure that token is not expire
            ClockSkew = TimeSpan.Zero,//is timespan zero,that is used to difference in times b / w two computers
            ValidIssuer = builder.Configuration["jWTSetting:Issuer"],
            ValidAudience = builder.Configuration["jWTSetting:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["jWTSetting:IssuerSigningKey"]))
        };
    });
// Add LinkedIn authentication services
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = "LinkedIn";
//})
//.AddCookie()
//.AddOpenIdConnect("LinkedIn", options =>
//{
//    options.ClientId = configuration["Authentication:LinkedIn:clientid"];
//    options.ClientSecret = configuration["Authentication:LinkedIn:clientSecret"];
//    options.Authority = "https://www.linkedin.com/oauth/v2/authorization";
//    options.CallbackPath = "/signin-linkedin";
//    options.ResponseType = "code";
//    options.UsePkce = true;
//    options.Scope.Clear();
//    options.Scope.Add("profile");
//    options.Scope.Add("email");
//    options.Scope.Add("openid");
//    options.SaveTokens = true;
//});

builder.Services.AddAuthentication("LinkedIn")
    .AddOAuth("LinkedIn", options =>
    {
        options.ClientId = configuration["Authentication:LinkedIn:clientid"];
        options.ClientSecret = configuration["Authentication:LinkedIn:clientSecret"];
        options.CallbackPath = "/signin-linkedin"; // The callback URL

        options.AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
        options.TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
        options.UserInformationEndpoint = "https://api.linkedin.com/v2/userinfo";
        options.ClaimsIssuer = "https://www.linkedin.com";
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "emailAddress");
        // options.UserInformationEndpoint = "https://api.linkedin.com/v2/userinfo?projection=(id,name,email)";
        options.ClaimActions.MapJsonKey("urn:linkedin:id", "id");
        options.ClaimActions.MapJsonKey("urn:linkedin:name", "name");
        options.ClaimActions.MapJsonKey("urn:linkedin:email", "email");
        options.SaveTokens = true;
        options.Scope.Clear();
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("openid");
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();
                var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                context.RunClaimActions(json.RootElement);
            }
        };


    });
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
//    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = "GitHub";
//})
//.AddCookie()
//.AddOAuth("GitHub", options =>
//{
//    options.ClientId = configuration["Authentication:Github:clientid"];
//    options.ClientSecret = configuration["Authentication:Github:clientSecret"];
//    options.CallbackPath = new PathString("/signin-github");
//    options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
//    options.TokenEndpoint = "https://github.com/login/oauth/access_token";
//    options.UserInformationEndpoint = "https://api.github.com/user";
//    options.SaveTokens = true;
//    // Retrieving user information is unique to each provider.
//    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
//    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
//    options.ClaimActions.MapJsonKey("urn:github:name", "name");
    
//    options.ClaimActions.MapJsonKey("urn:github:url", "html_url");
//    options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");
//    options.ClaimActions.MapJsonKey("urn:github:email", "email");
//    options.ClaimActions.MapJsonKey("urn:github:email", "useremail");

//    options.Events = new OAuthEvents
//    {
//        OnCreatingTicket = async context =>
//        {
//            // Get the GitHub user
//            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
//            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
//            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
//            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
//            response.EnsureSuccessStatusCode();
//            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
//            context.RunClaimActions(json.RootElement);
//        }
//    };
//    //options?.Invoke(options);

//});
//Facebook Authentication Services
builder.Services.AddAuthentication().AddFacebook(LinkedinOptions =>
{
    LinkedinOptions.AppId = configuration["Authentication:Facebook:AppId"];
    LinkedinOptions.AppSecret = configuration["Authentication:Facebook:AppSecret"];
});
//Google Authentication Services
builder.Services.AddAuthentication().AddGoogle(googleOptions =>
{
    googleOptions.ClientId = configuration["Authentication:Google:ClientId"];
    googleOptions.ClientSecret = configuration["Authentication:Google:ClientSecret"];
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            new string[] { }
        }
    });
});
//Cors Policy
builder.Services.AddCors(options => {
    options.AddPolicy("AllowAll",
        b => b.AllowAnyMethod()
        .AllowAnyHeader()
        .AllowAnyOrigin());
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseAuthentication();    
app.UseAuthorization();

app.MapControllers();


app.Run();
