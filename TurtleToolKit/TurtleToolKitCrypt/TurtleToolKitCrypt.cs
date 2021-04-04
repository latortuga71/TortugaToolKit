using System;
using System.IO;
using System.Security.Cryptography;

namespace TurtleToolKitCrypt
{
    class Cryptor
    {
        public byte[] Encryptionkey;
        public byte[] Iv;
        public Cryptor(byte[] key, byte[] iv)
        {
            Encryptionkey = key;
            Iv = iv;
        }
        public byte[] EncryptFile(string fileToEncrypt)
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(fileToEncrypt);
                Aes aes = Aes.Create();
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;
                aes.Key = Encryptionkey;
                aes.IV = Iv;
                var encrypter = aes.CreateEncryptor(aes.Key, aes.IV);
                var encryptedBytes = PerformEncryption(bytes, encrypter);
                Console.WriteLine("::: Successfully encrypted file :::");
                return encryptedBytes;
            }
            catch
            {
                Console.WriteLine("::: Failed to encrypt file :::");
                return null;
            }
        }

        public byte[] EncryptBytes(byte[] bytesToEncrypt)
        {
            try
            {
                Aes aes = Aes.Create();
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;
                aes.Key = Encryptionkey;
                aes.IV = Iv;
                var encrypter = aes.CreateEncryptor(aes.Key, aes.IV);
                var encryptedBytes = PerformEncryption(bytesToEncrypt, encrypter);
                Console.WriteLine("::: Successfully encrypted Bytes :::");
                return encryptedBytes;
            }
            catch
            {
                Console.WriteLine("::: Failed to encrypt Bytes :::");
                return null;
            }
        }
        public byte[] DecryptFile(string fileToDecrypt)
        {
            try
            {
                byte[] bytesToDecrypt = File.ReadAllBytes(fileToDecrypt);
                Aes aes = Aes.Create();
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;
                aes.Key = Encryptionkey;
                aes.IV = Iv;
                var decrypter = aes.CreateDecryptor(aes.Key, aes.IV);
                var decryptedBytes = PerformEncryption(bytesToDecrypt, decrypter);
                Console.WriteLine("::: Successfully decrypted file :::");
                return decryptedBytes;
            }
            catch
            {
                Console.WriteLine("::: Failed to decrypt file :::");
                return null;
            }
        }

        public byte[] DecryptBytes(byte[] bytesToDecrypt)
        {
            try
            {
                Aes aes = Aes.Create();
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;
                aes.Key = Encryptionkey;
                aes.IV = Iv;
                var decrypter = aes.CreateDecryptor(aes.Key, aes.IV);
                var decryptedBytes = PerformEncryption(bytesToDecrypt, decrypter);
                Console.WriteLine("::: Successfully decrypted bytes :::");
                return decryptedBytes;
            }
            catch
            {
                Console.WriteLine("::: Failed to decrypt bytes :::");
                return null;
            }
        }
        private byte[] PerformEncryption(byte[] data, ICryptoTransform cryptoTransform)
        {
            MemoryStream ms = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();
            return ms.ToArray();
        }
    }
}
