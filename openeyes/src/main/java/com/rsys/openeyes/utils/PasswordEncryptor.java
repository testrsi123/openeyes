package com.rsys.openeyes.utils;

import java.security.AlgorithmParameters;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This file used for Password Encryptor.
 * 
 */
public class PasswordEncryptor {
	
	/** LOGGER  **/
	private static final Logger LOGGER = LoggerFactory.getLogger(PasswordEncryptor.class);
	
	/** AES CBC PKCS5 PADDING */
	private static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
	
	/** ENCODING_TYPE */
	private static final String ENCODING_TYPE = "UTF-8";

	/** Hexa decimal number */
	private static char[] toHex = { '0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	
	private static String password = "openeyes";
    private static String salt;
    private static int pswdIterations = 65536  ;
    private static int keySize = 128;
    private static byte[] ivBytes;

    
	/**
	 * Private constructor
	 */
	private PasswordEncryptor() {
		
	}
	
	public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String s = new String(bytes);
        return s;
    }
	
	/**
	 * Returns a value after decrypting a provided password.
	 * But ENABLEPINENCRYPTION is false then return 4-digit pin value.
	 *
	 * @param encodepwd
	 * @return 
	 */
	public static String decrypt(String encodepwd) {
		

		if (encodepwd == null || "".equals(encodepwd)) {
			return null;
		}

		try {
			
			//
			byte[] saltBytes = salt.getBytes(ENCODING_TYPE);
			byte[] decodePassword = org.apache.commons.codec.binary.Base64.decodeBase64(hex2ByteArray(encodepwd));
	 
	        // Derive the key
	        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	        PBEKeySpec spec = new PBEKeySpec(
	        		password.toCharArray(), 
	                saltBytes, 
	                pswdIterations, 
	                keySize
	                );
	 
	        SecretKey secretKey = factory.generateSecret(spec);
	        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        // Decrypt the message
	        Cipher decryptCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
	        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
	     
	        return  new String(decryptCipher.doFinal(decodePassword), ENCODING_TYPE);
			
		} catch (Exception ex) {
			System.out.println(" Error in decryption "+ex.getCause());
			LOGGER.error(ex.getMessage(), ex);
		}
		return null;
	}

	/**
	 * Returns a value after encrypting a provided password.
	 * But ENABLEPINENCRYPTION is false then return 4-digit pin value.
	 *
	 * @param password
	 * @return byte[]
	 */
	public static String encrypt(String textToEncrypt) {		
		if (textToEncrypt == null || "".equals(textToEncrypt)) {
			return null;
		}		
		salt = generateSalt();      
     
		try {
    		byte[] saltBytes = salt.getBytes("UTF-8");
    		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    		PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
                );
    		SecretKey secretKey = factory.generateSecret(spec);
    		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");		   
			
			final Cipher encryptCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
			encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	        AlgorithmParameters params = encryptCipher.getParameters();
	        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
	        final byte[] encrypt = encryptCipher.doFinal(textToEncrypt.getBytes(ENCODING_TYPE));
			return toHexString(Base64.encodeBase64(encrypt));
		} catch (Exception ex) {
			System.out.println(" Error in encryption "+ex.getCause());
			LOGGER.error(ex.getMessage(), ex);
		}
		return null;
	}

	/**
	 * Returns Hex value after encrypting a password
	 *
	 * @param b
	 * @return String
	 *
	 */
	private static String toHexString(byte[] b) {
		int pos = 0;
		char[] c = new char[b.length * 2];

		for (int i = 0; i < b.length; i++) {
			c[pos] = toHex[(b[i] >> 4) & 0x0F];
			pos++;
			c[pos] = toHex[b[i] & 0x0f];
			pos++;
		}
		return new String(c);
	}

	/**
	 * Returns byte array value from Hex encrypted a password
	 *
	 * @param hex
	 * @return String
	 *
	 */
	private static byte[] hex2ByteArray(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
					.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}

	/**
     * If pin start with zero then make 4-digit pin for encryption.
     *
     * @param pin
     * @return
     */
    public static String make4DigitPinStartWithZero(Long pin) {
    	StringBuilder sb = new StringBuilder();
    	String p = pin.toString();
    	for(int x = 4 - p.length(); x > 0; x--) {
    		sb.append("0");
    	}
    	return sb.append(p).toString();
    }
    
    public static void main(String[] args) {
    	String  encryptedPassword =  encrypt("admin123");
    	String  decryptedPassword =  decrypt(encryptedPassword);
    	System.out.println("encryptedPassword = "+encryptedPassword);
    	System.out.println("decryptedPassword = "+decryptedPassword);
	}

}