package com.ornach.andcryptz;


import android.util.Base64;

public class AesConfiguration {

	public static final int BASE64 = 0x00000000;
	public static final int HEX = 0x00000002;

	public Builder builder;

	public AesConfiguration(Builder builder) {
		this.builder = builder;
	}

	/**
	 * This class is used to create an AES Encryption instance, you should provide ALL data or start
	 * with the Default Builder provided.
	 */
	public static class Builder {

		private String charset = "UTF-8";
		private int base64Mode = Base64.NO_WRAP;
		private int interactionCount = 1000;
		private int keyLength = 128; // Generate a 128-bit key
		//private static int saltLength = KEY_LENGTH/8;
		private int ivSize = 16;
		private int keySize = keyLength / 8;
		private String cipherTransformation = "AES/CBC/PKCS7PADDING";
		private String algorithm = "AES";
		private String secretKeyAlgorithm = "PBKDF2WithHmacSHA1";
		private int encodeType = BASE64;

		private byte[] iv = new byte[ivSize];


		public Builder getDefaultBuilder() {
			Builder builder = new Builder()
				  .setCharset("UTF-8")
				  .setBase64Mode(Base64.NO_WRAP)
				  .setInteractionCount(1000)
				  .setKeyLength(128)
				  .setCipherTransformation("AES/CBC/PKCS7PADDING")
				  .setAlgorithm("AES")
				  .setSecretKeyAlgorithm("PBKDF2WithHmacSHA1")
				  .setEncodeType(BASE64);

			builder.keySize = Math.round(keyLength/8);

			return builder;
		}


		public AesConfiguration build(){
			return new AesConfiguration(this);
		}

		public String getCharset() {
			return charset;
		}

		public Builder setCharset(String charset) {
			this.charset = charset;
			return this;
		}

		public int getBase64Mode() {
			return base64Mode;
		}

		public Builder setBase64Mode(int base64Mode) {
			this.base64Mode = base64Mode;
			return this;
		}

		public int getInteractionCount() {
			return interactionCount;
		}

		public Builder setInteractionCount(int interactionCount) {
			this.interactionCount = interactionCount;
			return this;
		}

		public int getKeyLength() {
			return keyLength;
		}

		public Builder setKeyLength(int keyLength) {
			this.keyLength = keyLength;
			return this;
		}

		public String getCipherTransformation() {
			return cipherTransformation;
		}

		public Builder setCipherTransformation(String transformation) {
			this.cipherTransformation = transformation;
			return this;
		}

		public String getAlgorithm() {

			return algorithm;
		}

		public Builder setAlgorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		public byte[] getIv() {
			return iv;
		}

		public Builder setIv(byte[] iv) {
			this.iv = iv;
			return this;
		}

		public String getSecretKeyAlgorithm() {
			return secretKeyAlgorithm;
		}

		public Builder setSecretKeyAlgorithm(String secretKeyAlgorithm) {
			this.secretKeyAlgorithm = secretKeyAlgorithm;
			return this;
		}

		public int getEncodeType() {
			return encodeType;
		}

		public Builder setEncodeType(int encodeType) {
			this.encodeType = encodeType;
			return this;
		}
	}
}
