using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.ComponentModel;

var rsaKey = RSA.Create();
rsaKey.ImportRSAPrivateKey(File.ReadAllBytes("key"), out _);

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowBlazorApp",
            builder =>
            {
                builder.WithOrigins("http://localhost:5279") // Replace with your Blazor app's domain
                       .AllowAnyHeader()
                       .AllowAnyMethod();
            });
    });

builder.Services.AddAuthentication("jwt")
    .AddJwtBearer("jwt", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = false,
            ValidateAudience = false
        };

        options.Events = new JwtBearerEvents()
        {
            OnMessageReceived = (context) =>
            {
                if (context.Request.Query.ContainsKey("t"))
                {
                    context.Token = context.Request.Query["t"];
                }
                return Task.CompletedTask;
            }
        };

        options.Configuration = new OpenIdConnectConfiguration()
        {
            SigningKeys = 
            {
                new RsaSecurityKey(rsaKey)
            }
        };

        options.MapInboundClaims = false;
    
    });

var app = builder.Build();

app.UseCors("AllowBlazorApp");

app.MapGet("/", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "empty");

app.MapGet("/jwt", () =>
{
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(rsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://localhost:5000",
        Subject = new ClaimsIdentity(new Claim[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("name", "John Doe"),
        }),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)

    });
    return token;
});

app.MapGet("/jwk", () =>
{
    var publickey = RSA.Create();
    publickey.ImportRSAPublicKey(rsaKey.ExportRSAPublicKey(), out _);
    var key = new RsaSecurityKey(publickey);
    return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
});

app.MapGet("/jwk-private", () =>
{
    var key = new RsaSecurityKey(rsaKey);
    return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
});

app.MapGet("/modulus-exponent", () =>
{
    var publickey = RSA.Create();
    publickey.ImportRSAPublicKey(rsaKey.ExportRSAPublicKey(), out _);
    var key = new RsaSecurityKey(publickey);
    var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);

    var modulusBytes = Base64UrlEncoder.DecodeBytes(jwk.N);
    var exponentBytes = Base64UrlEncoder.DecodeBytes(jwk.E);

    // Convert bytes to whatever format you need
    // ...

    return new { Modulus = jwk.N, Exponent = jwk.E };
});

app.MapGet("/pem-public", () =>
{
    string publickey = File.ReadAllText("id-rsa.pub");
    return publickey;
});

app.MapGet("/pem-private", () =>
{
    string privatekey = File.ReadAllText("id-rsa");
    return privatekey;
});

app.Run();