﻿namespace HybridEncription
{
    partial class Form1
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.textBoxPlainTextAlice = new System.Windows.Forms.TextBox();
            this.lbl1 = new System.Windows.Forms.Label();
            this.buttonGenKey = new System.Windows.Forms.Button();
            this.buttonEncryptAes = new System.Windows.Forms.Button();
            this.textBoxEncryptedMessageAlice = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.textBoxBobOpenKey = new System.Windows.Forms.TextBox();
            this.buttonEncryptKeyRSA = new System.Windows.Forms.Button();
            this.buttonSendKeyMessage = new System.Windows.Forms.Button();
            this.textBoxBobPrivateKey = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.buttonDecryptSeessionKey = new System.Windows.Forms.Button();
            this.buttonDecryptMessageAes = new System.Windows.Forms.Button();
            this.labelSessionKey = new System.Windows.Forms.Label();
            this.labelDecryptedKey = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.labelSessionKey);
            this.groupBox1.Controls.Add(this.buttonSendKeyMessage);
            this.groupBox1.Controls.Add(this.buttonEncryptKeyRSA);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.textBoxEncryptedMessageAlice);
            this.groupBox1.Controls.Add(this.buttonEncryptAes);
            this.groupBox1.Controls.Add(this.buttonGenKey);
            this.groupBox1.Controls.Add(this.lbl1);
            this.groupBox1.Controls.Add(this.textBoxPlainTextAlice);
            this.groupBox1.Location = new System.Drawing.Point(13, 22);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(289, 353);
            this.groupBox1.TabIndex = 0;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Алиса";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.textBox1);
            this.groupBox2.Controls.Add(this.label4);
            this.groupBox2.Controls.Add(this.labelDecryptedKey);
            this.groupBox2.Controls.Add(this.buttonDecryptMessageAes);
            this.groupBox2.Controls.Add(this.buttonDecryptSeessionKey);
            this.groupBox2.Controls.Add(this.textBoxBobPrivateKey);
            this.groupBox2.Controls.Add(this.label3);
            this.groupBox2.Controls.Add(this.textBoxBobOpenKey);
            this.groupBox2.Controls.Add(this.label2);
            this.groupBox2.Location = new System.Drawing.Point(348, 22);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(358, 353);
            this.groupBox2.TabIndex = 1;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Боб";
            // 
            // textBoxPlainTextAlice
            // 
            this.textBoxPlainTextAlice.Location = new System.Drawing.Point(6, 37);
            this.textBoxPlainTextAlice.Multiline = true;
            this.textBoxPlainTextAlice.Name = "textBoxPlainTextAlice";
            this.textBoxPlainTextAlice.Size = new System.Drawing.Size(239, 52);
            this.textBoxPlainTextAlice.TabIndex = 0;
            // 
            // lbl1
            // 
            this.lbl1.AutoSize = true;
            this.lbl1.Location = new System.Drawing.Point(7, 18);
            this.lbl1.Name = "lbl1";
            this.lbl1.Size = new System.Drawing.Size(68, 13);
            this.lbl1.TabIndex = 1;
            this.lbl1.Text = "Сообщение:";
            // 
            // buttonGenKey
            // 
            this.buttonGenKey.Location = new System.Drawing.Point(10, 95);
            this.buttonGenKey.Name = "buttonGenKey";
            this.buttonGenKey.Size = new System.Drawing.Size(234, 23);
            this.buttonGenKey.TabIndex = 2;
            this.buttonGenKey.Text = "1.Generate session key";
            this.buttonGenKey.UseVisualStyleBackColor = true;
            this.buttonGenKey.Click += new System.EventHandler(this.buttonGenKey_Click);
            // 
            // buttonEncryptAes
            // 
            this.buttonEncryptAes.Location = new System.Drawing.Point(11, 157);
            this.buttonEncryptAes.Name = "buttonEncryptAes";
            this.buttonEncryptAes.Size = new System.Drawing.Size(234, 23);
            this.buttonEncryptAes.TabIndex = 3;
            this.buttonEncryptAes.Text = "2.Encrypt message AES";
            this.buttonEncryptAes.UseVisualStyleBackColor = true;
            this.buttonEncryptAes.Click += new System.EventHandler(this.buttonEncryptAes_Click);
            // 
            // textBoxEncryptedMessageAlice
            // 
            this.textBoxEncryptedMessageAlice.Location = new System.Drawing.Point(10, 204);
            this.textBoxEncryptedMessageAlice.Multiline = true;
            this.textBoxEncryptedMessageAlice.Name = "textBoxEncryptedMessageAlice";
            this.textBoxEncryptedMessageAlice.Size = new System.Drawing.Size(235, 52);
            this.textBoxEncryptedMessageAlice.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(11, 187);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(153, 13);
            this.label1.TabIndex = 5;
            this.label1.Text = "Зашифрованное сообщение:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(18, 18);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(87, 13);
            this.label2.TabIndex = 0;
            this.label2.Text = "Открытый ключ";
            // 
            // textBoxBobOpenKey
            // 
            this.textBoxBobOpenKey.Location = new System.Drawing.Point(21, 35);
            this.textBoxBobOpenKey.Name = "textBoxBobOpenKey";
            this.textBoxBobOpenKey.Size = new System.Drawing.Size(314, 20);
            this.textBoxBobOpenKey.TabIndex = 1;
            // 
            // buttonEncryptKeyRSA
            // 
            this.buttonEncryptKeyRSA.Location = new System.Drawing.Point(14, 263);
            this.buttonEncryptKeyRSA.Name = "buttonEncryptKeyRSA";
            this.buttonEncryptKeyRSA.Size = new System.Drawing.Size(231, 23);
            this.buttonEncryptKeyRSA.TabIndex = 6;
            this.buttonEncryptKeyRSA.Text = "3.Encrypt session key RSA";
            this.buttonEncryptKeyRSA.UseVisualStyleBackColor = true;
            this.buttonEncryptKeyRSA.Click += new System.EventHandler(this.buttonEncryptKeyRSA_Click);
            // 
            // buttonSendKeyMessage
            // 
            this.buttonSendKeyMessage.Location = new System.Drawing.Point(14, 304);
            this.buttonSendKeyMessage.Name = "buttonSendKeyMessage";
            this.buttonSendKeyMessage.Size = new System.Drawing.Size(231, 23);
            this.buttonSendKeyMessage.TabIndex = 7;
            this.buttonSendKeyMessage.Text = "4.Send key and message to Bob";
            this.buttonSendKeyMessage.UseVisualStyleBackColor = true;
            this.buttonSendKeyMessage.Click += new System.EventHandler(this.buttonSendKeyMessage_Click);
            // 
            // textBoxBobPrivateKey
            // 
            this.textBoxBobPrivateKey.Location = new System.Drawing.Point(21, 93);
            this.textBoxBobPrivateKey.Name = "textBoxBobPrivateKey";
            this.textBoxBobPrivateKey.Size = new System.Drawing.Size(314, 20);
            this.textBoxBobPrivateKey.TabIndex = 3;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(18, 76);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(87, 13);
            this.label3.TabIndex = 2;
            this.label3.Text = "Закрытый ключ";
            // 
            // buttonDecryptSeessionKey
            // 
            this.buttonDecryptSeessionKey.Location = new System.Drawing.Point(21, 127);
            this.buttonDecryptSeessionKey.Name = "buttonDecryptSeessionKey";
            this.buttonDecryptSeessionKey.Size = new System.Drawing.Size(314, 23);
            this.buttonDecryptSeessionKey.TabIndex = 4;
            this.buttonDecryptSeessionKey.Text = "5. Decrypt session key RSA";
            this.buttonDecryptSeessionKey.UseVisualStyleBackColor = true;
            this.buttonDecryptSeessionKey.Click += new System.EventHandler(this.buttonDecryptSeessionKey_Click);
            // 
            // buttonDecryptMessageAes
            // 
            this.buttonDecryptMessageAes.Location = new System.Drawing.Point(21, 177);
            this.buttonDecryptMessageAes.Name = "buttonDecryptMessageAes";
            this.buttonDecryptMessageAes.Size = new System.Drawing.Size(314, 23);
            this.buttonDecryptMessageAes.TabIndex = 5;
            this.buttonDecryptMessageAes.Text = "6. Decrypt message AES";
            this.buttonDecryptMessageAes.UseVisualStyleBackColor = true;
            this.buttonDecryptMessageAes.Click += new System.EventHandler(this.buttonDecryptMessageAes_Click);
            // 
            // labelSessionKey
            // 
            this.labelSessionKey.AutoSize = true;
            this.labelSessionKey.Location = new System.Drawing.Point(11, 125);
            this.labelSessionKey.Name = "labelSessionKey";
            this.labelSessionKey.Size = new System.Drawing.Size(67, 13);
            this.labelSessionKey.TabIndex = 8;
            this.labelSessionKey.Text = "Session key:";
            // 
            // labelDecryptedKey
            // 
            this.labelDecryptedKey.AutoSize = true;
            this.labelDecryptedKey.Location = new System.Drawing.Point(21, 158);
            this.labelDecryptedKey.Name = "labelDecryptedKey";
            this.labelDecryptedKey.Size = new System.Drawing.Size(79, 13);
            this.labelDecryptedKey.TabIndex = 6;
            this.labelDecryptedKey.Text = "Decrypted key:";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(21, 219);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(156, 13);
            this.label4.TabIndex = 7;
            this.label4.Text = "Расшифрованное сообщение";
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(24, 244);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(311, 66);
            this.textBox1.TabIndex = 8;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(751, 399);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Name = "Form1";
            this.Text = "Гибридное шифрование AES/RSA";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.TextBox textBoxEncryptedMessageAlice;
        private System.Windows.Forms.Button buttonEncryptAes;
        private System.Windows.Forms.Button buttonGenKey;
        private System.Windows.Forms.Label lbl1;
        private System.Windows.Forms.TextBox textBoxPlainTextAlice;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBoxBobOpenKey;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button buttonEncryptKeyRSA;
        private System.Windows.Forms.Button buttonSendKeyMessage;
        private System.Windows.Forms.Button buttonDecryptSeessionKey;
        private System.Windows.Forms.TextBox textBoxBobPrivateKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label labelSessionKey;
        private System.Windows.Forms.Label labelDecryptedKey;
        private System.Windows.Forms.Button buttonDecryptMessageAes;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label label4;
    }
}

