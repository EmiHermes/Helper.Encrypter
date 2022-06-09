using System;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Windows.Forms;
using CommonServices.Common;

namespace Conciety.IQon2014.Services.Helper.Encrypter
{
    /// <summary>
    /// Encrypter Form.
    /// </summary>
    public partial class FrmEncrypter : Form
    {
        #region Encryption Key
        static private readonly string EncryptionKey = ConfigurationManager.AppSettings["EncryptionKey"];
        #endregion

        #region Encryption Type
        private static readonly Encryption.EncryptionAlgorithm Algorithm = Encryption.GetEncryptionGeneralType(ConfigurationManager.AppSettings["EncryptionType"]);
        #endregion

        #region Error Messages
        private const string MsgImpossibleToEncrypt = " There is NOTHING on the TextBox to Encrypt! ";
        private const string MsgImpossibleToEncryptTittle = " IMPOSSIBLE TO ENCRYPT ";
        private const string MsgImpossibleToDencrypt = " There is NOTHING on the TextBox to Decrypt! ";
        private const string MsgImpossibleToDencryptTitle = " IMPOSSIBLE TO DECRYPT ";
        #endregion

        #region FORM
        /// <summary>
        /// Initializing Form.
        /// </summary>
        public FrmEncrypter()
        {
            InitializeComponent();
        }
        /// <summary>
        /// FORM LOAD.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Form1_Load(object sender, EventArgs e)
        {
            // Cleaning TextBoxes and hidding the message
            CleanTexBoxes();
        }
        #endregion
        
        #region BUTTONS
        /// <summary>
        /// Button to ENCRYPT the text.
        /// </summary>
        /// <param name="sender">Sender.</param>
        /// <param name="e">Params.</param>
        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            // Cleaning the result textbox
            txtFinal.Text = string.Empty;
            // Checking if there is something to be changed
            if (!string.IsNullOrEmpty(txtOriginal.Text.Trim()))
            {
                txtFinal.Text = Encryption.Encrypt(txtOriginal.Text.Trim(), Algorithm, EncryptionKey);
                lblDone.Visible = true;
            }
            else
            {
                MessageBox.Show(MsgImpossibleToEncrypt, MsgImpossibleToEncryptTittle, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }
        /// <summary>
        /// Button to DECRYPT the text.
        /// </summary>
        /// <param name="sender">Sender.</param>
        /// <param name="e">Params.</param>
        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            // Cleaning the result textbox
            txtFinal.Text = string.Empty;
            // Checking if there is something to be changed
            if (!string.IsNullOrEmpty(txtOriginal.Text.Trim()))
            {
                txtFinal.Text = Encryption.Decrypt(txtOriginal.Text.Trim(), Algorithm, EncryptionKey);
                lblDone.Visible = true;
            }
            else
            {
                MessageBox.Show(MsgImpossibleToDencrypt, MsgImpossibleToDencryptTitle, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }
        /// <summary>
        /// Button to clean the TextBoxes.
        /// </summary>
        /// <param name="sender">Sender.</param>
        /// <param name="e">Params.</param>
        private void button1_Click(object sender, EventArgs e)
        {
            CleanTexBoxes();
        }
        #endregion

        #region PRIVATE METHODS
        /// <summary>
        /// It cleans all the TextBoxes.
        /// </summary>
        private void CleanTexBoxes()
        {
            txtOriginal.Text = string.Empty;
            txtFinal.Text = string.Empty;
            lblDone.Visible = false;
        }
        #endregion
    }
}
