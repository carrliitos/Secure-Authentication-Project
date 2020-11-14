package RSA;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;

public class Cryptosystem {
	private static long executionTime = -1;
	private static long startTime;

	public static byte[] encrypt(byte[] plainText, PublicKey Key) {
		initStartTime();

		BigInteger e = Key.getE();
		BigInteger n = Key.getN();
		int bitLength = Key.getN().bitLength();
		int plainTextBlockSize = getPlainTextBlockSize(bitLength);
		int cipherTextBlockSize = getCipherTextBlockSize(bitLength);

		byte padded[] = pad(plainText, plainTextBlockSize);
		byte block[][] = split(padded, plainTextBlockSize);
		BigInteger encrypted[] = new BigInteger[block.length];
		for(int i = 0; i < encrypted.length; ++i) {
			encrypted[i] = new BigInteger(1, block[i]).modPow(e, n);
		}

		byte cipherText[] = new byte[encrypted.length * cipherTextBlockSize];
		for(int i = 0; i < encrypted.length; ++i){
			byte cipher[] = encrypted[i].toByteArray();
			int offset = i * cipherTextBlockSize + cipherTextBlockSize - cipher.length;
			for(int j = 0; j < cipher.length; ++j) {
				cipherText[j + offset] = cipher[j];
			}
		}

		calculateExecutionTime();
		return cipherText;
	}

	public static byte[] decrypt(byte[] cipherText, PrivateKey Key) throws Exception {
		initStartTime();

		BigInteger d = Key.getD();
		BigInteger n = Key.getN();
		int bitLength = Key.getN().bitLength();
		int plainBlockSize = getPlainTextBlockSize(bitLength);
		int cipherBlockSize = getCipherTextBlockSize(bitLength);

		if(cipherText.length % cipherBlockSize != 0) {
			throw new Exception("密文的长度非法");
		}
		byte[][] block = split(cipherText, cipherBlockSize);
		BigInteger[] decrypted = new BigInteger[block.length];
		for(int i = 0; i < decrypted.length; ++i) {
			decrypted[i] = new BigInteger(block[i]).modPow(d, n);
		}

		byte[] plainText = new byte[decrypted.length * plainBlockSize];
		for(int i = 0; i< decrypted.length; ++i) {
			byte[] plain = decrypted[i].toByteArray();
			for(int j = Math.max(plainBlockSize - plain.length, 0); j < plainBlockSize; ++j) {
				plainText[i * plainBlockSize + j] = plain[j + plain.length - plainBlockSize];
			}
		}

		plainText = unpad(plainText, plainBlockSize);
		calculateExecutionTime();
		return plainText;
	}

	public static KeyPair generateKeyPair(int bitLength) {
		RSA rsa = new RSA(bitLength);
		return new KeyPair(new PublicKey(rsa.getE(), rsa.getN()), new PrivateKey(rsa.getD(), rsa.getN()));
	}

	private static byte[][] split(byte[] text, int blockSize) {
		byte block[][] = new byte[text.length/blockSize][blockSize];
		for(int i = 0; i < block.length; ++i) {
			for(int j = 0; j < blockSize; ++j) {
				block[i][i] = text[i * blockSize + j];
			}
		}
		return block;
	}
}