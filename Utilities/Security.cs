#region "copyright"

/*
    Copyright (c) 2024 Dale Ghent <daleg@elemental.org>

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/
*/

#endregion "copyright"

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DaleGhent.NINA.GroundStation.Utilities
{

    /// <summary>
    /// Cross-platform credential encryption helper.
    ///
    /// Windows: uses DPAPI (ProtectedData) — existing encrypted profiles continue to work unchanged.
    /// Linux:   uses AES-256-GCM with a PBKDF2-derived key (machine-id + username).
    ///          Linux-encrypted values are stored with an "lx:" prefix to distinguish them from
    ///          Windows DPAPI blobs, so profiles can be read on the correct platform.
    /// </summary>
    public class Security
    {

        private const string LinuxPrefix = "lx:";
        private const int AesKeySize = 32;   // 256-bit
        private const int AesNonceSize = 12;  // 96-bit nonce (GCM standard)
        private const int AesTagSize = 16;   // 128-bit authentication tag

        // ── Public API ────────────────────────────────────────────────────────

        public static string Encrypt(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                return string.Empty;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return EncryptWindows(secret);
            }

            return LinuxPrefix + EncryptLinux(secret);
        }

        public static string Decrypt(string cipher)
        {
            if (string.IsNullOrEmpty(cipher))
            {
                return string.Empty;
            }

            if (cipher.StartsWith(LinuxPrefix, StringComparison.Ordinal))
            {
                return DecryptLinux(cipher[LinuxPrefix.Length..]);
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return DecryptWindows(cipher);
            }

            // Legacy DPAPI blob on Linux — cannot decrypt, return empty
            return string.Empty;
        }

        // ── Windows (DPAPI) ───────────────────────────────────────────────────

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Only called on Windows")]
        private static string EncryptWindows(string secret)
        {
            try
            {
                byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
                byte[] cipherBytes = ProtectedData.Protect(secretBytes, null, DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(cipherBytes);
            }
            catch
            {
                return string.Empty;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Only called on Windows")]
        private static string DecryptWindows(string cipher)
        {
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipher);
                byte[] plainBytes = ProtectedData.Unprotect(cipherBytes, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch
            {
                return string.Empty;
            }
        }

        // ── Linux (AES-256-GCM) ───────────────────────────────────────────────

        /// <summary>
        /// Stored format (all base64): nonce(12) | tag(16) | ciphertext(N)
        /// </summary>
        private static string EncryptLinux(string secret)
        {
            try
            {
                byte[] key = DeriveLinuxKey();
                byte[] plaintext = Encoding.UTF8.GetBytes(secret);
                byte[] nonce = new byte[AesNonceSize];
                RandomNumberGenerator.Fill(nonce);
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[AesTagSize];

                using AesGcm aes = new AesGcm(key, AesTagSize);
                aes.Encrypt(nonce, plaintext, ciphertext, tag);

                byte[] blob = new byte[AesNonceSize + AesTagSize + ciphertext.Length];
                Buffer.BlockCopy(nonce, 0, blob, 0, AesNonceSize);
                Buffer.BlockCopy(tag, 0, blob, AesNonceSize, AesTagSize);
                Buffer.BlockCopy(ciphertext, 0, blob, AesNonceSize + AesTagSize, ciphertext.Length);

                return Convert.ToBase64String(blob);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string DecryptLinux(string cipher)
        {
            try
            {
                byte[] blob = Convert.FromBase64String(cipher);
                if (blob.Length < AesNonceSize + AesTagSize)
                {
                    return string.Empty;
                }

                byte[] key = DeriveLinuxKey();
                byte[] nonce = new byte[AesNonceSize];
                byte[] tag = new byte[AesTagSize];
                byte[] ciphertext = new byte[blob.Length - AesNonceSize - AesTagSize];

                Buffer.BlockCopy(blob, 0, nonce, 0, AesNonceSize);
                Buffer.BlockCopy(blob, AesNonceSize, tag, 0, AesTagSize);
                Buffer.BlockCopy(blob, AesNonceSize + AesTagSize, ciphertext, 0, ciphertext.Length);

                byte[] plaintext = new byte[ciphertext.Length];
                using AesGcm aes = new AesGcm(key, AesTagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);

                return Encoding.UTF8.GetString(plaintext);
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Derives a 256-bit AES key from the machine-id and current username via PBKDF2-SHA256.
        /// Falls back to the hostname when /etc/machine-id is not available.
        /// </summary>
        private static byte[] DeriveLinuxKey()
        {
            string machineId;
            try
            {
                machineId = File.ReadAllText("/etc/machine-id").Trim();
            }
            catch
            {
                machineId = Environment.MachineName;
            }

            byte[] password = Encoding.UTF8.GetBytes(Environment.UserName);
            byte[] salt = Encoding.UTF8.GetBytes(machineId);

            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations: 200_000, HashAlgorithmName.SHA256, AesKeySize);
        }
    }
}