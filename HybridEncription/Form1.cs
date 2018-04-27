using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Security.Cryptography;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace HybridEncription
{
    public partial class Form1 : Form
    {
        string sessionkey = "";
        byte[] BytesSessionkey;
        string bobOpenKey = "";
        //byte[] bobOpenKeyBytes;
        string bobPrivateKey = "";
        //byte[] bobPrivateKeyBytes;

        string plaintext = "";
        string encryptedMessage = "";
        byte[] encryptedMessageBytes;
        string encryptedSessionKey = "";
        byte[] encryptedSessionKeyBytes;

        string decryptedMessage = "";
        byte[] decryptedSessionKeyBytes;
        string decryptedSessionKey = "";

        //rsa
        RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
        RSAParameters priv_key;
        RSAParameters pub_key;
        
        //BouncyCastle RSA
        byte[] BouncyEncryptedSessionKeyBytes;
        string BouncyEncryptedSessionKey = "";
        byte[] BouncyDecryptedSessionKeyBytes;
        string BouncyDecryptedSessionKey = "";
        string publicKey = "-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\r\n-----END PUBLIC KEY-----";
        string privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQXGukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63ilAkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlFL0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5kX6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2eplU9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=\r\n-----END RSA PRIVATE KEY-----";
        TFRSAEncryption RSA_BOUNCY_enc = new TFRSAEncryption();

        public Form1()
        {
            InitializeComponent();
            //var cp = new CspParameters();
            //cp.KeyContainerName = "KeyContainerName";
            ////cp.
            //csp = new RSACryptoServiceProvider(cp);
            //make a new csp with a new keypair
            csp = new RSACryptoServiceProvider();
        }

        private void buttonGenKey_Click(object sender, EventArgs e)
        {
            //generate random 256-bit (32 bytes) key
            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[32];
                random.GetBytes(key);
                sessionkey = Convert.ToBase64String(key);
                BytesSessionkey = key;
            }
                //sessionkey = (Guid.NewGuid()).ToString();
                labelSessionKey.Text = sessionkey;
        }

        private void buttonEncryptAes_Click(object sender, EventArgs e)
        {
            plaintext = textBoxPlainTextAlice.Text;
            //byte[] bytesKey = Encoding.UTF8.GetBytes(sessionkey);
            // Encrypt the string to an array of bytes. 
            byte[] encrypted = AES.EncryptStringToBytes_Aes(plaintext, BytesSessionkey);

            encryptedMessage = Convert.ToBase64String(encrypted);
            encryptedMessageBytes = encrypted;
            textBoxEncryptedMessageAlice.Text = encryptedMessage;
            //Console.WriteLine("Encrypted (b64-encode): {0}", );
        }

        private void buttonEncryptKeyRSA_Click(object sender, EventArgs e)
        {
            byte[] data = BytesSessionkey;

            csp.ImportParameters(pub_key);//using public bob key
            var encData = csp.Encrypt(data, false); // encrypt with PKCS#1_V1.5 Padding
            encryptedSessionKeyBytes = encData;
            encryptedSessionKey = Convert.ToBase64String(encryptedSessionKeyBytes);
            labelEncKey.Text = encryptedSessionKey;
            //bouncy RSA
            
            // Set up 
            var input = "Perceived determine departure explained no forfeited";
            
            // Encrypt it
            var encryptedWithPublic = RSA_BOUNCY_enc.RsaEncryptWithPublic(input, publicKey);

            var encryptedWithPrivate = RSA_BOUNCY_enc.RsaEncryptWithPrivate(input, privateKey);

            // Decrypt
            var output1 = RSA_BOUNCY_enc.RsaDecryptWithPrivate(encryptedWithPublic, privateKey);

            var output2 = RSA_BOUNCY_enc.RsaDecryptWithPublic(encryptedWithPrivate, publicKey);

            //string priv = Convert.ToBase64String(Encoding.UTF8.GetBytes(bobPrivateKey));
            //string priv = Convert.ToBase64String(Encoding.UTF8.GetBytes("OLOLO"));
            //string pub = Convert.ToBase64String(Encoding.UTF8.GetBytes("TROLOLO"));
            //RsaPrivateCrtKeyParameters privateKeyParameters = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(priv));
            //AsymmetricKeyParameter publicKeyInfoParameters = PublicKeyFactory.CreateKey(Convert.FromBase64String(pub));
            //byte[] clearData = BytesSessionkey;
            //string algorithm = "RSA/ECB/PKCS1Padding";

            //var cipherOne = CipherUtilities.GetCipher(algorithm);
            //cipherOne.Init(true, privateKeyParameters);
            //byte[] signedData = cipherOne.DoFinal(clearData);

            //var clientTwo = CipherUtilities.GetCipher(algorithm);
            //clientTwo.Init(false, publicKeyInfoParameters);
            //var clearDataTwo = clientTwo.DoFinal(signedData);

            //System.Diagnostics.Debug.Assert(Convert.ToBase64String(clearData) == Convert.ToBase64String(clearDataTwo));


            MessageBox.Show("Ok");

        }

        private void buttonSendKeyMessage_Click(object sender, EventArgs e)
        {
            //все нужные переменные уже есть
            if (encryptedSessionKeyBytes != null && encryptedMessageBytes != null)
                MessageBox.Show("Ok");
            else
                MessageBox.Show("something went wrong...");

        }

        private void buttonDecryptSeessionKey_Click(object sender, EventArgs e)
        {
            //not working...
            //var dd = csp.Decrypt(encryptedSessionKeyBytes,false);
            //var dkey = Convert.ToBase64String(dd);

            //decrypt with own BigInteger based implementation
            var decBytes = MyRSAImpl.plainDecryptPriv(encryptedSessionKeyBytes, priv_key); 
            var decData = decBytes.SkipWhile(x => x != 0).Skip(1).ToArray();//strip PKCS#1_V1.5 padding
            decryptedSessionKeyBytes = decData;
            decryptedSessionKey = Convert.ToBase64String(decryptedSessionKeyBytes);

            labelDecryptedKey.Text = decryptedSessionKey;

            //using BouncyCastle

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            //rsa
            pub_key = csp.ExportParameters(false); // export public key
            priv_key = csp.ExportParameters(true); // export private key


            //bobOpenKey = (Guid.NewGuid()).ToString();
            //bobPrivateKey = (Guid.NewGuid()).ToString();
            bobOpenKey = csp.ToXmlString(false);
            bobPrivateKey = csp.ToXmlString(true);
            textBoxBobOpenKey.Text = bobOpenKey;//rsaParamString(pub_key);
            textBoxBobPrivateKey.Text = bobPrivateKey;
        }
        private string rsaParamString(RSAParameters key)
        {
            string d = key.D == null ? "" : Convert.ToBase64String(key.D);
            string m = key.Modulus == null ? "" : Convert.ToBase64String(key.Modulus);
            string p = key.P == null ? "" : Convert.ToBase64String(key.P);

            string dp = key.P == null ? "" : Convert.ToBase64String(key.DP);
            string dq = key.P == null ? "" : Convert.ToBase64String(key.DQ);
            string exp = key.P == null ? "" : Convert.ToBase64String(key.Exponent);
            return  d+ m + p+dp+dq+exp;
        }
        private void buttonDecryptMessageAes_Click(object sender, EventArgs e)
        {
            var res = AES.DecryptStringFromBytes_Aes(encryptedMessageBytes, decryptedSessionKeyBytes);
            decryptedMessage = res;
            textBoxDecryptedMessage.Text = res;
        }
    }
}
