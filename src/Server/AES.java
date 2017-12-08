package Server;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
	public static final int BLOCK_LENGTH = 16;
	public static final int KEY_LENGTH = 16;
	private static final String KEY_ALGORITHM = "AES";
	private static final String ECB_CIPHER = "AES/ECB/NoPadding";
	private static final String CBC_CIPHER = "AES/CBC/PKCS5Padding";
	
	private static Key toKey(byte[] key) {
		SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
		return secretKey;
	}
	
	public static byte[] encrypt(byte[] data, byte[] key) throws InvalidKeyException, IllegalBlockSizeException {
		Key k = toKey(key);
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ECB_CIPHER);
		} catch ( Exception e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		cipher.init(Cipher.ENCRYPT_MODE, k);
		try {
			return cipher.doFinal(data);
		} catch ( BadPaddingException e ) {
			throw new RuntimeException("unexpected exception", e);
		}
	}
	
	public static byte[] decrypt(byte[] data, byte[] key) throws InvalidKeyException, IllegalBlockSizeException {
		Key k = toKey(key);
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ECB_CIPHER);
		} catch ( Exception e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		cipher.init(Cipher.DECRYPT_MODE, k);
		try {
			return cipher.doFinal(data);
		} catch ( BadPaddingException e ) {
			throw new RuntimeException("unexpected exception", e);
		}
	}
	
	public static byte[] cbcEncrypt(byte[] data, byte[] key, byte[] iv) throws InvalidKeyException {
		Key k = toKey(key);
		IvParameterSpec ivspec = new IvParameterSpec(iv);  //wrap into ivspec
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CBC_CIPHER);
		} catch ( Exception e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		try {
			cipher.init(Cipher.ENCRYPT_MODE, k, ivspec);
		} catch ( InvalidAlgorithmParameterException e ) {
			throw new RuntimeException("unexpected exception", e);
		}

		try {
			return cipher.doFinal(data);
		} catch ( Exception e ) {
			throw new RuntimeException("unexpected exception", e);
		}
	}
	
	public static byte[] cbcDecrypt(byte[] data, byte[] key, byte[] iv) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Key k = toKey(key);
		IvParameterSpec ivspec = new IvParameterSpec(iv);  //wrap into ivspec
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CBC_CIPHER);
		} catch ( Exception e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, k, ivspec);
		} catch ( InvalidAlgorithmParameterException e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		return cipher.doFinal(data);
	}
	
	public static byte[] initKey() {
		KeyGenerator kg;
		try {
			kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		} catch ( NoSuchAlgorithmException e ) {
			throw new RuntimeException("unexpected exception", e);
		}
		kg.init(KEY_LENGTH*8);
		SecretKey secretKey = kg.generateKey();
		return secretKey.getEncoded();
	}
}
