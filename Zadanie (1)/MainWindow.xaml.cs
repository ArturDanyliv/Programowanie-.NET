using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace EncryptionApp
{
    public partial class MainWindow : Window
    {
        private SymmetricAlgorithm algorithm;
        private byte[] key;
        private byte[] iv;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void GenerateKeysButton_Click(object sender, RoutedEventArgs e)
        {
            switch (AlgorithmComboBox.SelectedIndex)
            {
                case 0:
                    algorithm = Aes.Create();
                    break;
                case 1:
                    algorithm = DES.Create();
                    break;
                case 2:
                    algorithm = TripleDES.Create();
                    break;
                default:
                    MessageBox.Show("Please select an algorithm.");
                    return;
            }

            algorithm.GenerateKey();
            algorithm.GenerateIV();
            key = algorithm.Key;
            iv = algorithm.IV;

            KeyTextBox.Text = BitConverter.ToString(key).Replace("-", "");
            IVTextBox.Text = BitConverter.ToString(iv).Replace("-", "");
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (algorithm == null)
            {
                MessageBox.Show("Please generate keys first.");
                return;
            }

            string plainText = PlainTextBox.Text;
            if (string.IsNullOrEmpty(plainText))
            {
                MessageBox.Show("Please enter plain text.");
                return;
            }

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            byte[] encryptedBytes = EncryptStringToBytes(plainText, key, iv);

            stopwatch.Stop();
            EncryptionTimeTextBox.Text = stopwatch.ElapsedMilliseconds + " ms";

            CipherTextBox.Text = Encoding.ASCII.GetString(encryptedBytes);
            HexTextBox.Text = BitConverter.ToString(encryptedBytes).Replace("-", "");
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (algorithm == null)
            {
                MessageBox.Show("Please generate keys first.");
                return;
            }

            string hexCipherText = HexTextBox.Text;
            if (string.IsNullOrEmpty(hexCipherText))
            {
                MessageBox.Show("Please enter cipher text in HEX.");
                return;
            }

            byte[] cipherBytes = HexStringToByteArray(hexCipherText);

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            string decryptedText = DecryptStringFromBytes(cipherBytes, key, iv);

            stopwatch.Stop();
            DecryptionTimeTextBox.Text = stopwatch.ElapsedMilliseconds + " ms";

            PlainTextBox.Text = decryptedText;
        }

        private byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;

            using (var encryptor = algorithm.CreateEncryptor(Key, IV))
            {
                byte[] inputBuffer = Encoding.UTF8.GetBytes(plainText);
                encrypted = encryptor.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
            }

            return encrypted;
        }

        private string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext;

            using (var decryptor = algorithm.CreateDecryptor(Key, IV))
            {
                byte[] outputBuffer = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                plaintext = Encoding.UTF8.GetString(outputBuffer);
            }

            return plaintext;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
