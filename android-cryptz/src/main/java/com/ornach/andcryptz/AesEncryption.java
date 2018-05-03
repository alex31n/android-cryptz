package com.ornach.andcryptz;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class AesEncryption {

	private static final int BASE64 = AesConfiguration.BASE64;
	private static final int HEX = AesConfiguration.HEX;

	private static String CHARSET = "UTF-8";
	private static int BASE64_MODE = Base64.NO_WRAP;
	private static int INTERACTION_COUNT = 1000;
	private static int KEY_LENGTH = 128;
	private static int KEY_SIZE = 16;
	private static final int IV_SIZE = 16;
	private static String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7PADDING";
	private static String CIPHER_ALGORITHM = "AES";
	private static String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
	//private static byte[] IV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	private static String IV = "0000000000000000";

	private static int encodeType = BASE64;

	/*private static byte[] getIv(){
		return  IV;
	}*/

	private static AesConfiguration config;
	private static AesConfiguration.Builder mBuilder;

	public static void addConfiguration(AesConfiguration configuration) {
		config = configuration;
		mBuilder = configuration.builder;
		CHARSET = mBuilder.getCharset();
		BASE64_MODE = mBuilder.getBase64Mode();
		INTERACTION_COUNT = mBuilder.getInteractionCount();
		KEY_LENGTH = mBuilder.getKeyLength();
		KEY_SIZE = Math.round(KEY_LENGTH / 8);
		CIPHER_TRANSFORMATION = mBuilder.getCipherTransformation();
		CIPHER_ALGORITHM = mBuilder.getAlgorithm();
		SECRET_KEY_ALGORITHM = mBuilder.getSecretKeyAlgorithm();
		encodeType = mBuilder.getEncodeType();
		//Log.e("TAG", "encodeType "+ encodeType);
	}

	private static byte[] getIv(byte[] ivs) {
		byte[] finalIvs = new byte[16];
		int len = ivs.length > 16 ? 16 : ivs.length;
		System.arraycopy(ivs, 0, finalIvs, 0, len);

		return finalIvs;
	}


	public static SecretKey generateKey(String key) throws UnsupportedEncodingException {
		byte[] keyBytes = key.getBytes(CHARSET);
		SecretKey secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);

		return secretKey;
	}


	public static SecretKey generatePBEKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/* Use this to derive the key from the password: */
		return generatePBEKey(key, "0");
	}

	public static SecretKey generatePBEKey(String key, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/* Use this to derive the key from the password: */
		/*KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt.getBytes(), INTERACTION_COUNT, KEY_LENGTH);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
		byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
		SecretKey secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
		return secretKey;*/
		return generatePBEKey(key, salt.getBytes());
	}

	public static SecretKey generatePBEKey(String key, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/* Use this to derive the key from the password: */
		KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, INTERACTION_COUNT, KEY_LENGTH);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
		byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
		return new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
	}


	public static String encrypt(final String key, String text) throws GeneralSecurityException {

		/*String result = null;
		try {
			SecretKey secretKey = KEY_LENGTH > 128 ? generatePBEKey(key) : generateKey(key);
			byte[] encryp = encrypt(secretKey, IV.getBytes(), text.getBytes(CHARSET));
			result = getTextFromByte(encryp);

		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new GeneralSecurityException(e);
		}

		return result;*/
		return encrypt(key, IV, text);
	}
	public static String encrypt(final String key, String iv, String text) throws GeneralSecurityException {

		String result = null;
		try {
			SecretKey secretKey = KEY_LENGTH > 128 ? generatePBEKey(key) : generateKey(key);
			byte[] encryp = encrypt(secretKey, iv.getBytes(), text.getBytes(CHARSET));
			result = getTextFromByte(encryp);

		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new GeneralSecurityException(e);
		}

		return result;
	}

	public static String encrypt(SecretKey secretKey, String text) throws GeneralSecurityException {
		String result = null;
		try {
			byte[] encryp = encrypt(secretKey, IV.getBytes(), text.getBytes(CHARSET));
			//result = Base64.encodeToString(encryp, BASE64_MODE);
			result = getTextFromByte(encryp);

		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new GeneralSecurityException(e);
		}
		return result;
	}


	public static byte[] encrypt(final SecretKey secretKey, final byte[] iv, final byte[] text) throws GeneralSecurityException {

		byte[] key = secretKey.getEncoded();
		//Log.e("TAG", "Key " + Base64.encodeToString(key,Base64.DEFAULT));
		SecretKeySpec skeySpec = new SecretKeySpec(key, CIPHER_ALGORITHM);
		//Log.e("TAG", "Key 2 " + Base64.encodeToString(skeySpec.getEncoded(),Base64.DEFAULT));
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		IvParameterSpec ivSpec = new IvParameterSpec(getIv(iv));
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

		byte[] encrypted = cipher.doFinal(text);

		return encrypted;
	}


	public static String decrypt(final String key, String text) throws GeneralSecurityException {
		/*String result = null;

		try {
			byte[] cipherByte = getByteFromText(text);
			SecretKey secretKey = KEY_LENGTH > 128 ? generatePBEKey(key) : generateKey(key);
			byte[] decryp = decrypt(secretKey, IV.getBytes(), cipherByte);
			result = new String(decryp, CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new GeneralSecurityException();
		}

		return result;*/
		return decrypt(key, IV, text);
	}

	public static String decrypt(final String key, String iv, String text) throws GeneralSecurityException {
		String result = null;

		try {
			byte[] cipherByte = getByteFromText(text);
			SecretKey secretKey = KEY_LENGTH > 128 ? generatePBEKey(key) : generateKey(key);
			byte[] decryp = decrypt(secretKey, iv.getBytes(), cipherByte);
			result = new String(decryp, CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new GeneralSecurityException();
		}

		return result;
	}





	public static String decrypt(SecretKey secretKey, String text) throws GeneralSecurityException {
		String result = null;
		try {
			byte[] cipherByte = getByteFromText(text);
			byte[] decryp = decrypt(secretKey, IV.getBytes(), cipherByte);
			result = new String(decryp, CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new GeneralSecurityException();
		}

		return result;
	}


	public static byte[] decrypt(final SecretKey secretKey, final byte[] iv, final byte[] decodedCipherText) throws GeneralSecurityException {

		byte[] key = secretKey.getEncoded();
		SecretKeySpec skeySpec = new SecretKeySpec(key, CIPHER_ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		IvParameterSpec ivSpec = new IvParameterSpec(getIv(iv));
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		byte[] decryptedBytes = cipher.doFinal(decodedCipherText);

		return decryptedBytes;
	}


	private static byte[] getByteFromText(String text) {
		byte[] byteArray = new byte[KEY_SIZE];
		if (encodeType == BASE64) {
			byteArray = Base64.decode(text, BASE64_MODE);
			//Log.e("TAG", "getByteFromText Base64: "+ byteArray.length);
		} else if (encodeType == HEX) {

			byteArray = hexToByte(text);

			//Log.e("TAG", "getByteFromText HEX: "+ byteArray.length);
		}

		return byteArray;
	}

	private static String getTextFromByte(byte[] byteArray) {
		String text = "";
		if (encodeType == BASE64) {
			text = Base64.encodeToString(byteArray, BASE64_MODE);
		} else if (encodeType == HEX) {

			final StringBuilder builder = new StringBuilder();
			for (byte b : byteArray) {
				builder.append(String.format("%02x", b));
			}

			text = builder.toString();
		}

		return text;
	}


	private static byte[] hexToByte(String text) {

		if ((text.length() % 2) != 0)
			throw new IllegalArgumentException("Input hex number must contain an even");

		byte[] b = new byte[text.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int index = i * 2;
			int v = Integer.parseInt(text.substring(index, index + 2), 16);
			b[i] = (byte) v;
		}

		return b;
	}

	/**
	 * @return a new pseudorandom salt of the specified length
	 */
	private static byte[] generateSalt(int length) {
		Random r = new SecureRandom();
		byte[] salt = new byte[length];
		r.nextBytes(salt);
		return salt;
	}
}
