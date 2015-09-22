package net.michaelbester.example;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


/**
 * An example of how to use PBKDF2 to hash passwords
 * This example uses the default Java Crypto libraries - so no new depedencies
 * 
 * @author michaelbester
 */
public class PBKDF2Example {
	
	/** 
	 * Iteration count of 10 000 is a recommended minimum 
	 * The more iterations you use the stronger the hash will be, 
	 * but this also has a performance impact.
	 */
	private static final int ITERATIONS = 10000; 
	
	/** key size for the PBKDF2 function */
	private static final int KEYSIZE = 256;
	
	/** 256 bits is the recommended salt size  */
	private static final int SALT_SIZE = 32;
	
	/** The SecretKey Factory Algorithm to generate the hash */
	private static final String PBKDF_ALGORITHM = "PBKDF2WithHmacSHA1";
	
	/** The Algorithm to use when generating the secure salt value */
	private static final String SECURERANDOM_ALGORITHM = "SHA1PRNG";
	
	private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

	
	/**
	 * Generates a hash of a cleartext password and also generates a Salt
	 * @param password
	 * @return
	 */
	public static String generateHash(String password) {
		try {
			byte[] salt = getSaltValue();
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEYSIZE);
			SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF_ALGORITHM);
			
			return bytesToHex(salt) + ":" + bytesToHex(skf.generateSecret(pbeKeySpec).getEncoded());
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		
		} catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
		}
		
		return null;
	}
	
	
	/**
	 * Generates a hash with a given Salt
	 * @param password
	 * @param salt
	 * @return
	 */
	public static String generateHash(String password, byte[] salt) {
		try {
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEYSIZE);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			
			return bytesToHex(skf.generateSecret(pbeKeySpec).getEncoded());
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());

		} catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
		}
		
		return null;
	}
	
	
	/**
	 * Verifies a provided cleartext password to a previously hashed value
	 * @param hashed_value
	 * @param clearPassword
	 * @return
	 */
	public static boolean verifyHash(String clearPassword, String hashed_value) {
		String salt = hashed_value.substring(0, hashed_value.indexOf(":"));
		String persisted_hash = hashed_value.substring(hashed_value.indexOf(":") + 1, hashed_value.length());
		
		String check_hash = generateHash(clearPassword, hexToByteArray(salt));
		
		if (persisted_hash.equals(check_hash)) {
			return Boolean.TRUE;
		}
		return Boolean.FALSE;
	}
	
	
	/** 
	 * Generates a Secure Random Salt
	 * 
	 * @return salt
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] getSaltValue() throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance(SECURERANDOM_ALGORITHM);
		byte[] salt = new byte [SALT_SIZE];
		random.nextBytes(salt);
		
		return salt;
	}
	
	
	/**
	 * Convert a Byte array to Hex String
	 * @param bytes
	 * @return
	 */
	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray [v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	
	/**
	 * Convert a Hex String to a Byte Array
	 * @param hexValue
	 * @return
	 */
	private static byte[] hexToByteArray(String hexValue) {
	    int length = hexValue.length();
	    byte[] value = new byte[length / 2];
	    for (int i = 0; i < length; i += 2) {
	        value[i / 2] = (byte) ((Character.digit(hexValue.charAt(i), 16) << 4)
	                             + Character.digit(hexValue.charAt(i+1), 16));
	    }
	    return value;
	}
	
	
	public static void main (String arg[]) {
		long start = System.currentTimeMillis();
		String hashedPw = generateHash("Password");
		long end = System.currentTimeMillis();
		
		System.out.println("PBKDF2 password: " + hashedPw + " took :" + (end - start) + " ms");
		
		Boolean correctPw = verifyHash("Password", hashedPw);
		System.out.println("Provided correct password: " + correctPw);
	}
}
