namespace Conciety.IQon2014.Services.Helper.Encrypter
{
    partial class FrmEncrypter
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FrmEncrypter));
            this.lblDone = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.btnDecrypt = new System.Windows.Forms.Button();
            this.btnEncrypt = new System.Windows.Forms.Button();
            this.txtFinal = new System.Windows.Forms.TextBox();
            this.txtOriginal = new System.Windows.Forms.TextBox();
            this.lblFinal = new System.Windows.Forms.Label();
            this.lblOriginal = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // lblDone
            // 
            this.lblDone.AutoSize = true;
            this.lblDone.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(64)))), ((int)(((byte)(0)))));
            this.lblDone.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblDone.ForeColor = System.Drawing.Color.Red;
            this.lblDone.Location = new System.Drawing.Point(162, 64);
            this.lblDone.Name = "lblDone";
            this.lblDone.Size = new System.Drawing.Size(103, 17);
            this.lblDone.TabIndex = 15;
            this.lblDone.Text = "CONVERTED";
            this.lblDone.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(192)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.button1.Location = new System.Drawing.Point(395, 147);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(118, 23);
            this.button1.TabIndex = 14;
            this.button1.Text = "CLEAN";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // btnDecrypt
            // 
            this.btnDecrypt.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(128)))), ((int)(((byte)(255)))), ((int)(((byte)(128)))));
            this.btnDecrypt.Location = new System.Drawing.Point(395, 58);
            this.btnDecrypt.Name = "btnDecrypt";
            this.btnDecrypt.Size = new System.Drawing.Size(118, 23);
            this.btnDecrypt.TabIndex = 13;
            this.btnDecrypt.Text = "DECRYPT";
            this.btnDecrypt.UseVisualStyleBackColor = false;
            this.btnDecrypt.Click += new System.EventHandler(this.btnDecrypt_Click);
            // 
            // btnEncrypt
            // 
            this.btnEncrypt.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(128)))), ((int)(((byte)(128)))));
            this.btnEncrypt.Location = new System.Drawing.Point(271, 58);
            this.btnEncrypt.Name = "btnEncrypt";
            this.btnEncrypt.Size = new System.Drawing.Size(118, 23);
            this.btnEncrypt.TabIndex = 12;
            this.btnEncrypt.Text = "ENCRYPT";
            this.btnEncrypt.UseVisualStyleBackColor = false;
            this.btnEncrypt.Click += new System.EventHandler(this.btnEncrypt_Click);
            // 
            // txtFinal
            // 
            this.txtFinal.ForeColor = System.Drawing.SystemColors.MenuHighlight;
            this.txtFinal.Location = new System.Drawing.Point(20, 88);
            this.txtFinal.Multiline = true;
            this.txtFinal.Name = "txtFinal";
            this.txtFinal.ReadOnly = true;
            this.txtFinal.Size = new System.Drawing.Size(493, 82);
            this.txtFinal.TabIndex = 11;
            // 
            // txtOriginal
            // 
            this.txtOriginal.Location = new System.Drawing.Point(20, 32);
            this.txtOriginal.Name = "txtOriginal";
            this.txtOriginal.Size = new System.Drawing.Size(493, 20);
            this.txtOriginal.TabIndex = 10;
            // 
            // lblFinal
            // 
            this.lblFinal.AutoSize = true;
            this.lblFinal.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(64)))), ((int)(((byte)(0)))));
            this.lblFinal.ForeColor = System.Drawing.Color.Lime;
            this.lblFinal.Location = new System.Drawing.Point(17, 72);
            this.lblFinal.Name = "lblFinal";
            this.lblFinal.Size = new System.Drawing.Size(98, 13);
            this.lblFinal.TabIndex = 9;
            this.lblFinal.Text = "Text CONVERTED";
            this.lblFinal.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // lblOriginal
            // 
            this.lblOriginal.AutoSize = true;
            this.lblOriginal.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(64)))), ((int)(((byte)(0)))));
            this.lblOriginal.ForeColor = System.Drawing.Color.Lime;
            this.lblOriginal.Location = new System.Drawing.Point(17, 15);
            this.lblOriginal.Name = "lblOriginal";
            this.lblOriginal.Size = new System.Drawing.Size(205, 13);
            this.lblOriginal.TabIndex = 8;
            this.lblOriginal.Text = "Text to be ENCRYPTED or DECRYPTED";
            this.lblOriginal.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // FrmEncrypter
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("$this.BackgroundImage")));
            this.ClientSize = new System.Drawing.Size(530, 184);
            this.Controls.Add(this.lblDone);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.btnDecrypt);
            this.Controls.Add(this.btnEncrypt);
            this.Controls.Add(this.txtFinal);
            this.Controls.Add(this.txtOriginal);
            this.Controls.Add(this.lblFinal);
            this.Controls.Add(this.lblOriginal);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.Fixed3D;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "FrmEncrypter";
            this.Text = "Encrypt / Decrypt";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblDone;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button btnDecrypt;
        private System.Windows.Forms.Button btnEncrypt;
        private System.Windows.Forms.TextBox txtFinal;
        private System.Windows.Forms.TextBox txtOriginal;
        private System.Windows.Forms.Label lblFinal;
        private System.Windows.Forms.Label lblOriginal;
    }
}

