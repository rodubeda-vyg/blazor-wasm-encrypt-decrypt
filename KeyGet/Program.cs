using System.Security.Cryptography;

var rsaKey = RSA.Create();
var privateKey = rsaKey.ExportRSAPrivateKeyPem();
var publicKey = rsaKey.ExportRSAPublicKeyPem();
File.WriteAllText("id-rsa", privateKey);
File.WriteAllText("id-rsa.pub", publicKey);