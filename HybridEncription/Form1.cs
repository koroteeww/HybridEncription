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

        string decryptedMessage = "";
        string decryptedSessionKey = "";

        public Form1()
        {
            InitializeComponent();
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
                labelSessionKey.Text = "Session key: "+sessionkey;
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

        }

        private void buttonSendKeyMessage_Click(object sender, EventArgs e)
        {

        }

        private void buttonDecryptSeessionKey_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            //generate random 256-bit (32 bytes) key
            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[32];
                random.GetBytes(key);
                bobOpenKey = Convert.ToBase64String(key);
                bobOpenKeyBytes = key;

                var key2 = new byte[32];
                random.GetBytes(key2);
                bobPrivateKey = Convert.ToBase64String(key2);
                bobPrivateKeyBytes = key2;
            }

            //bobOpenKey = (Guid.NewGuid()).ToString();
            //bobPrivateKey = (Guid.NewGuid()).ToString();
            textBoxBobOpenKey.Text = bobOpenKey;
            textBoxBobPrivateKey.Text = bobPrivateKey;
        }

        private void buttonDecryptMessageAes_Click(object sender, EventArgs e)
        {

        }
    }
}
