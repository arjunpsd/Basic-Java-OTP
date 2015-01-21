package org.arctix.security.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import org.arctix.security.hmac.HMACEngine;
import org.arctix.security.hmac.RandomNumberGenerator;
import org.junit.Before;
import org.junit.Test;

public class TestHMacEngine extends TestCase {
	
	private SecretKey key = null;
	private String algorithm = "HmacSHA1";
	private String[] params = null;
	private String code = null;
	
	
	@Before
	public void setUp() throws Exception{
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

}
