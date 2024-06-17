using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace external;

public class Service
{
    public async Task<string> Encrypt(string message)
    {
        using var httpClient = new HttpClient();
        var pem = await httpClient.GetStringAsync("https://localhost:5000/pem-public");
        var textReader = new StringReader(pem);
        var pemReader = new PemReader(textReader);
        var rsaParams = (RsaKeyParameters)pemReader.ReadObject();
        var cipher = CipherUtilities.GetCipher("RSA/None/OAEPWithSHA256AndMGF1Padding");
        cipher.Init(true, rsaParams);
        var encrypted = cipher.DoFinal(Encoding.UTF8.GetBytes(message));
        return Convert.ToBase64String(encrypted);
    }   

    public async Task<string> Decrypt(string encryptedMessage)
    {
        using var httpClient = new HttpClient();
        var pem = await httpClient.GetStringAsync("https://localhost:5000/pem-private");
        var textReader = new StringReader(pem);
        var pemReader = new PemReader(textReader);
        var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        var rsaParams = (RsaKeyParameters)keyPair.Private;
        var cipher = CipherUtilities.GetCipher("RSA/None/OAEPWithSHA256AndMGF1Padding");
        cipher.Init(false, rsaParams);
        var decrypted = cipher.DoFinal(Convert.FromBase64String(encryptedMessage));
        return Encoding.UTF8.GetString(decrypted);
    }
}
