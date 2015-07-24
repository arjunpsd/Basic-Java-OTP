package com.arctix.security.otp.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import com.arctix.security.otp.OTP;
import com.arctix.security.otp.RandomNumberGenerator;
import com.arctix.security.otp.hmac.HMACEngine;

import junit.framework.TestCase;

public class TestHMacEngine extends TestCase {

	private SecretKey key = null;
	private String algorithm = "HmacSHA1";
	private String[] params = null;
	private String code = null;

	@Before
	public void setUp() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		key = keyGen.generateKey();

		RandomNumberGenerator rng = RandomNumberGenerator.getInstance();
		code = String.valueOf(rng.getRandomInt());
		assertNotNull(code);
		params = new String[] { "0010000123434343" };
	}

	@Test
	public void testHmacCode() {

		HMACEngine engine = HMACEngine.getInstance(key, algorithm);
		String hmac = engine.generateHMAC(code, params);
		assertNotNull(hmac);
		assertTrue(engine.validateHMAC(hmac, code, params));

	}

	@Test
	public void testCheckSum() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		key = keyGen.generateKey();

		RandomNumberGenerator rng = RandomNumberGenerator.getInstance();
		for (int i = 0; i < 100; i++) {
			int code = rng.getRandomInt();
			assertFalse(code == 0);
			OTP otp = new OTP(String.valueOf(code), "");
			OTP otpWithCheckSum = otp.generateChecksum();
			System.out.println("Original OTP = " + otp.getPassword());
			System.out.println("OTP with CheckSum = " + otpWithCheckSum.getPassword());
			assertTrue(otpWithCheckSum.hasValidChecksum());
		}

	}

}
