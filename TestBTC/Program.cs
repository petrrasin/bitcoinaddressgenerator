using SshNet.Security.Cryptography;
using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace TestBTC
{
	class Program
	{
		static void Main(string[] args)
		{
			if (args?.Length != 1)
			{
				Console.WriteLine("Need private the key as an argument (hex sha256 format).");
				return;
			}

			var privateKey = args[0];

			var btc = new BitcoinWallletGenerator();
			var pubKey = btc.GetPublicKey(privateKey);
			var walletAddress = btc.GetWalletAddress(pubKey);

			Console.WriteLine($"Public key: {ByteArrayToString(pubKey)}");
			Console.WriteLine("");			
			Console.WriteLine($"Bitcoin address : {walletAddress}");

		}

		public static string ByteArrayToString(byte[] ba)
		{
			StringBuilder hex = new StringBuilder(ba.Length * 2);
			foreach (byte b in ba)
				hex.AppendFormat("{0:x2}", b);
			return hex.ToString();
		}
	}

	class BitcoinWallletGenerator
	{
		private const string base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

		private byte[] StringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
		}
		private string Base58Encode(byte[] data)
		{
			BigInteger intData = 0;
			for (int i = 0; i < data.Length; i++)
			{
				intData = intData * 256 + data[i];
			}

			string result = "";
			while (intData > 0)
			{
				int remainder = (int)(intData % 58);
				intData /= 58;
				result = base58Chars[remainder] + result;
			}

			// Append `1` for each leading 0 byte
			for (int i = 0; i < data.Length && data[i] == 0; i++)
			{
				result = '1' + result;
			}
			return result;
		}

		public byte[] GetPublicKey(string publicKeyInHexFormat)
		{
			return Cryptography.ECDSA.Secp256K1Manager.GetPublicKey(StringToByteArray(publicKeyInHexFormat), false);
		}

		public string GetWalletAddress(byte[] publicKey)
		{
			var sha256Hash = new SHA256();
			var ripemd160Hash = new RIPEMD160();

			var hashForRipe = sha256Hash.ComputeHash(publicKey);
			var hashRipe = ripemd160Hash.ComputeHash(hashForRipe);

			byte[] hashRipeAddLeadingZero = new byte[hashRipe.Length + 1];
			hashRipeAddLeadingZero[0] = 0x00;
			Array.Copy(hashRipe, 0, hashRipeAddLeadingZero, 1, hashRipe.Length);
			hashRipe = hashRipeAddLeadingZero;

			var checksumHash = sha256Hash.ComputeHash(sha256Hash.ComputeHash(hashRipeAddLeadingZero)).ToArray().Take(4).ToArray();

			var finalHash = new byte[hashRipe.Length + checksumHash.Length];
			hashRipe.CopyTo(finalHash, 0);
			checksumHash.CopyTo(finalHash, hashRipe.Length);

			sha256Hash.Dispose();
			ripemd160Hash.Dispose();

			return $"{Base58Encode(finalHash)}";

		}

	}
}