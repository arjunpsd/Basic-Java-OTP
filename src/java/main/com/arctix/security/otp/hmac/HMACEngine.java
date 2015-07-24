package com.arctix.security.otp.hmac;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Generates a random number and an associated HMAC for validation.
 * 
 * @author aprasa2
 *
 */
public class HMACEngine {

	private Mac macEngine = null;

	/**
	 * Parameterized constructor. Creates new instance of Mac Engine.
	 * Re-initializes Random Number generator.
	 * 
	 * @param key
	 * @param algorithm
	 */
	protected HMACEngine(SecretKey key, String algorithm) {
		try {
			macEngine = Mac.getInstance(algorithm);
			macEngine.init(key);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Get instance of HMAC Engine. Instance is not thread-safe. So returns new
	 * instance everytime.
	 * 
	 * @param key - Secret Key for generating HMAC
	 * @return
	 */
	public static HMACEngine getInstance(SecretKey key) {
		return new HMACEngine(key, "HmacSHA1");
	}

	public static HMACEngine getInstance(SecretKey key, String algorithm) {
		return new HMACEngine(key, algorithm);
	}

	/**
	 * Generates HMAC for the given text and extra params
	 * 
	 * @param text
	 * @param params
	 * @return
	 */
	public String generateHMAC(String text, String[] params) {
		macEngine.update(text.getBytes());
		for (String param : params) {
			macEngine.update(param.getBytes());
		}
		byte[] hmac = macEngine.doFinal();
		return byte2hex(hmac);
	}

	/**
	 * Validates the text using the HMAC. Returns true if valid. False
	 * otherwise.
	 * 
	 * @param params
	 * @param code
	 * @return
	 */
	public boolean validateHMAC(String providedHmac, String text, String[] params) {
		macEngine.update(text.getBytes());
		for (String param : params) {
			macEngine.update(param.getBytes());
		}
		byte[] hmac = macEngine.doFinal();

		String generatedHmac = byte2hex(hmac);

		if (generatedHmac.equals(providedHmac.toUpperCase())) {
			return true;
		}
		return false;
	}

	/*
	 * Converts a byte array to hex digit and writes to the supplied buffer
	 */
	private String byte2hex(byte[] b) {
		StringBuffer buf = new StringBuffer();
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

		for (int i = 0; i < b.length; i++) {
			int high = ((b[i] & 0xf0) >> 4);
			int low = (b[i] & 0x0f);
			buf.append(hexChars[high]);
			buf.append(hexChars[low]);
		}
		return buf.toString();
	}
}
