package com.xiaolin.api.utils;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;


public class CryptographyUtil {

	public static String getCryString(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
		Random ran = new Random();
		byte[] salt = new byte[16];
		ran.nextBytes(salt);
		byte[] encryptedPassword = getEncryptedPassword(password, salt, 10000, 32);
		byte[] bytes = composeIdentityV3Hash(salt, 10000, encryptedPassword);
		return Base64.encodeBase64String(bytes);
	}

	public static boolean verifyCryString(String password, String passwordHash)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		return verifyIdentityV3Hash(password, passwordHash);
	}

	private static byte[] getEncryptedPassword(String password, byte[] salt, int iterations, int derivedKeyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength * 8);

		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		return f.generateSecret(spec).getEncoded();
	}

	private static byte[] intToByte(int num) {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) ((num >> 24) & 0xff);
		bytes[1] = (byte) ((num >> 16) & 0xff);
		bytes[2] = (byte) ((num >> 8) & 0xff);
		bytes[3] = (byte) (num & 0xff);
		return bytes;
	}

	private static int byte2Int(byte[] bytes) {
		return (bytes[0] & 0xff) << 24 | (bytes[1] & 0xff) << 16 | (bytes[2] & 0xff) << 8 | (bytes[3] & 0xff);
	}

	private static byte[] composeIdentityV3Hash(byte[] salt, int iterationCount, byte[] passwordHash) {
		byte[] hash = new byte[1 + 4/* KeyDerivationPrf value */ + 4/* Iteration count */ + 4/* salt size */
				+ salt.length /* salt */ + 32 /* password hash size */];
		hash[0] = 1; // Identity V3 marker

		System.arraycopy(intToByte(1), 0, hash, 1, 4);
		System.arraycopy(intToByte(iterationCount), 0, hash, 1 + 4, 4);
		System.arraycopy(intToByte(salt.length), 0, hash, 1 + 2 * 4, 4);
		System.arraycopy(salt, 0, hash, 1 + 3 * 4, salt.length);
		System.arraycopy(passwordHash, 0, hash, 1 + 3 * 4 + salt.length, passwordHash.length);
		return hash;
	}

	private static boolean verifyIdentityV3Hash(String password, String passwordHash)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] identityV3HashArray = DatatypeConverter.parseBase64Binary(passwordHash);

		if (identityV3HashArray[0] != 1) {
			throw new InvalidKeySpecException("passwordHash is not Identity V3");
		}
		byte[] prfAsArray = new byte[4];
		System.arraycopy(identityV3HashArray, 1, prfAsArray, 0, 4);
		int prf = byte2Int(prfAsArray);

		byte[] itearationCountAsArray = new byte[4];
		System.arraycopy(identityV3HashArray, 5, itearationCountAsArray, 0, 4);
		int iterationCount = byte2Int(itearationCountAsArray);

		byte[] saltSizeAsArray = new byte[4];
		System.arraycopy(identityV3HashArray, 9, saltSizeAsArray, 0, 4);
		int saltSize = byte2Int(saltSizeAsArray);

		byte[] salt = new byte[saltSize];
		System.arraycopy(identityV3HashArray, 13, salt, 0, saltSize);

		byte[] saveHashedPassword = new byte[identityV3HashArray.length - 1 - 4 - 4 - 4 - saltSize];
		System.arraycopy(identityV3HashArray, 13 + saltSize, saveHashedPassword, 0, saveHashedPassword.length);

		byte[] hashFromInputPassword = getEncryptedPassword(password, salt, iterationCount, 32);

		return Arrays.equals(saveHashedPassword, hashFromInputPassword);
	}
}
