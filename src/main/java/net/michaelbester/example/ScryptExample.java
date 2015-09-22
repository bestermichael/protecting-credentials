package net.michaelbester.example;

import com.lambdaworks.crypto.SCryptUtil;

/**
 * An example of how to use Scrypt to hash passwords
 * This example uses the LamdaWorks library (https://github.com/wg/scrypt) 
 * 
 * The configured values for N, R and P are the recommended minimum.
 * 
 * You only need to store the hashed value - you do not need N, R or P.
 * You do not need to generate or store a salt - this library does it for you.
 * 
 * @author michaelbester
 */
public class ScryptExample {

	/** The General work factor, iteration count */
	private static final int N = 16384; 
	
	/** The block size in use for the underlying hash; finetunes the relative memory cost */
	private static final int R = 8;
	
	/** Parallization factor; finetunes the relative CPU cost */
	private static final int P = 1;
	
	public static void main (String args[]) {
		
		long start = System.currentTimeMillis();
		String hashedPw = SCryptUtil.scrypt("Password", N, R, P);
		long end = System.currentTimeMillis();
	
		System.out.println("Scrypt password: " + hashedPw + " took :"
				+ (end - start) + " ms");

		//To verify a password:
		boolean correctPw = SCryptUtil.check("Password", hashedPw);
		System.out.println("Provided correct password: " + correctPw);
	}
}
