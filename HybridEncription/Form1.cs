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

namespace HybridEncription
{
    public partial class Form1 : Form
    {
        string sessionkey = "";
        byte[] Bsessionkey;
        string bobOpenKey = "";
        byte[] bobOpenKeyBytes;
        string bobPrivateKey = "";
        byte[] bobPrivateKeyBytes;

        string plaintext = "";
        string encryptedMessage = "";
        byte[] encryptedBytes;
        string encryptedSessionKey = "";
        byte[] encryptedSessionKeyBytes;

        string decryptedMessage = "";
        byte[] decryptedSessionKeyBytes;
        string decryptedSessionKey = "";

        RSACryptoServiceProvider csp = new RSACryptoServiceProvider();//make a new csp with a new keypair
        RSAParameters priv_key;
        RSAParameters pub_key;

        public Form1()
        {
            InitializeComponent();
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
                Bsessionkey = key;
            }
                //sessionkey = (Guid.NewGuid()).ToString();
                labelSessionKey.Text = sessionkey;
        }

        private void buttonEncryptAes_Click(object sender, EventArgs e)
        {
            plaintext = textBoxPlainTextAlice.Text;
            //byte[] bytesKey = Encoding.UTF8.GetBytes(sessionkey);
            // Encrypt the string to an array of bytes. 
            byte[] encrypted = AES.EncryptStringToBytes_Aes(plaintext, Bsessionkey);
            encryptedMessage = Convert.ToBase64String(encrypted);
            encryptedBytes = encrypted;
            textBoxEncryptedMessageAlice.Text = encryptedMessage;
            //Console.WriteLine("Encrypted (b64-encode): {0}", );
        }

        private void buttonEncryptKeyRSA_Click(object sender, EventArgs e)
        {
            byte[] data = Bsessionkey;

            csp.ImportParameters(pub_key);//using public bob key
            var encData = csp.Encrypt(data, false); // encrypt with PKCS#1_V1.5 Padding
            encryptedSessionKeyBytes = encData;
            encryptedSessionKey = Convert.ToBase64String(encryptedSessionKeyBytes);
            labelEncKey.Text = encryptedSessionKey;
            MessageBox.Show("Ok");

        }

        private void buttonSendKeyMessage_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Ok");
        }

        private void buttonDecryptSeessionKey_Click(object sender, EventArgs e)
        {
            //decrypt with own BigInteger based implementation
            var decBytes = MyRSAImpl.plainDecryptPriv(encryptedSessionKeyBytes, priv_key); 
            var decData = decBytes.SkipWhile(x => x != 0).Skip(1).ToArray();//strip PKCS#1_V1.5 padding
            decryptedSessionKeyBytes = decData;
            decryptedSessionKey = Convert.ToBase64String(decryptedSessionKeyBytes);

            labelDecryptedKey.Text = decryptedSessionKey;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            //generate random 256-bit (32 bytes) key
            pub_key = csp.ExportParameters(false); // export public key
            priv_key = csp.ExportParameters(true); // export private key


            //bobOpenKey = (Guid.NewGuid()).ToString();
            //bobPrivateKey = (Guid.NewGuid()).ToString();
            textBoxBobOpenKey.Text = rsaParamString(pub_key);
            textBoxBobPrivateKey.Text = rsaParamString(priv_key);
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
            var res = AES.DecryptStringFromBytes_Aes(encryptedBytes, decryptedSessionKeyBytes);
            textBoxDecryptedMessage.Text = res;
        }
    }
}
