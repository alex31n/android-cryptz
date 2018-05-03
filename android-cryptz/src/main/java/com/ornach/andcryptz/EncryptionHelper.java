package com.ornach.andcryptz;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionHelper {

	public final static String KEY = "1234567890123456";
	public final static String IV = "1234567890123456";

	public static byte[] encrypt(byte[] data, byte[] key, byte[] ivs) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			//Log.e("TAG", "Key 3 " + Base64.encodeToString(secretKeySpec.getEncoded(), Base64.DEFAULT));
			byte[] finalIvs = new byte[16];
			int len = ivs.length > 16 ? 16 : ivs.length;
			System.arraycopy(ivs, 0, finalIvs, 0, len);
			IvParameterSpec ivps = new IvParameterSpec(finalIvs);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivps);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}



	public static byte[] decrypt(byte[] data, byte[] key, byte[] ivs) {

		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			byte[] finalIvs = new byte[16];
			int len = ivs.length > 16 ? 16 : ivs.length;
			System.arraycopy(ivs, 0, finalIvs, 0, len);
			IvParameterSpec ivps = new IvParameterSpec(finalIvs);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivps);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
}
