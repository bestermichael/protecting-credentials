package net.michaelbester.example;

import org.springframework.security.crypto.bcrypt.BCrypt;

/**
 * An example of how to use BCrypt to hash passwords This example uses the
 * Spring Security implementation - this means much cleaner code.
 * 
 * @author michaelbester
 */
public class BcryptExample {

	public static void main(String args[]) {
		long start = System.currentTimeMillis();
		/**
		 * Hashing the password only needs this one line - important to note,
		 * you can also use this library to generate the salt.
		 * 
		 * I used a work factor of 12 here. (10 is the default - you can go up to 31).
		 * The higher this value, the longer the hash takes.
		 */
		String hashedPw = BCrypt.hashpw("Password", BCrypt.gensalt(12));

		long end = System.currentTimeMillis();
		System.out.println("BCrypt password: " + hashedPw + " took :"
				+ (end - start) + " ms");

		boolean correctPw = BCrypt.checkpw("Passowrd", hashedPw);
		System.out.println("Provided correct password: " + correctPw);
	}
}
