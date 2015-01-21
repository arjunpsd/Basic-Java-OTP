package org.arctix.security.hmac;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RandomNumberGenerator {

	private SecureRandom rngEngine = null;

	private int DEFAULT_SEED = 4;

	private int DEFAULT_MAX = 99999999;

	private String DEFAULT_ALGORITHM = "SHA1PRNG";

	private static RandomNumberGenerator instance = null;

	private RandomNumberGenerator() {
		try {
			rngEngine = SecureRandom.getInstance(DEFAULT_ALGORITHM);
			rngEngine.setSeed(rngEngine.generateSeed(DEFAULT_SEED));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static RandomNumberGenerator getInstance() {
		if (instance == null) {
			instance = new RandomNumberGenerator();
		}
		return instance;
	}
	
	public void randomize(){
		if (rngEngine != null) {
			rngEngine.generateSeed(DEFAULT_SEED);
		}
	}
	
	public int getRandomInt(){
		return Math.abs(rngEngine.nextInt(DEFAULT_MAX));
	}

}
