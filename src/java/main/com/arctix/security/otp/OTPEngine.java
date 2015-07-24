package com.arctix.security.otp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.crypto.SecretKey;

import org.apache.commons.lang.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arctix.security.otp.hmac.HMACEngine;

/**
 * One time password generator using HMAC validation. Generates a numeric
 * password and an associated HMAC that can be used for validating the password
 * later.
 * 
 * @author aprasa2
 *
 */
public class OTPEngine extends HMACEngine {

	private RandomNumberGenerator rngInstance;

	private final DateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmm");

	static final int TIME_LAP_INTERVAL = 5; // in minutes

	static final int PASSWORD_EXPRIRY = 15; // in minutes

	static final int MAX_ATTEMPTS = 5; // number of attempts allowed to
										// validate an OTP

	private static Logger logger = LoggerFactory.getLogger(OTPEngine.class);

	TimeLaps timeLapGenerator;

	private Counter counterProvider;

	/**
	 * Parameterized constructor. Creates new instance of OTP Engine.
	 * Re-initializes Random Number generator.
	 * 
	 * @param key
	 * @param algorithm
	 */
	private OTPEngine(SecretKey key, String algorithm, Counter counterProvider) {
		super(key, algorithm);
		if (rngInstance == null) {
			rngInstance = RandomNumberGenerator.getInstance();
			timeLapGenerator = new TimeLaps(TIME_LAP_INTERVAL);
			this.counterProvider = counterProvider;
		}
	}

	/**
	 * Returns new instance of OTP Engine. The instance is not thread-safe. Do
	 * not use this method in production. Use one that provides concrete
	 * implementation of Counter Provider
	 * 
	 * @param key
	 *            - Secret key for generating HMAC
	 * @return
	 */
	public static OTPEngine getInstance(SecretKey key) {
		logger.warn("Using In-Memory Counter!! Not recommended for production deployments");
		return getInstance(key, "HmacSHA1", new InMemoryCounter());
	}

	/**
	 * Returns new instance of OTP Engine. The instance is not thread-safe.
	 * 
	 * @param key
	 * @param counterProvider
	 * @return
	 */
	public static OTPEngine getInstance(SecretKey key, Counter counterProvider) {
		return getInstance(key, "HmacSHA1", counterProvider);
	}

	/**
	 * Returns new instance of OTP Engine. The instance is not thread-safe.
	 * 
	 * @param key
	 * @param algorithm
	 * @param counterProvider
	 * @return
	 */
	public static OTPEngine getInstance(SecretKey key, String algorithm, Counter counterProvider) {
		return new OTPEngine(key, algorithm, counterProvider);
	}

	/**
	 * Generates a one-time password based on the given parameter strings.
	 * 
	 * @param params
	 * @return
	 */
	public OTP generatePasswordWithHmac(final String params[]) {

		// generate a random password
		String password = Integer.toString(rngInstance.getRandomInt());

		// Include start of last time lap as one of the parameters in generating
		// HMAC
		TimeLaps timeLaps = new TimeLaps(TIME_LAP_INTERVAL);
		Calendar lastTimeLap = timeLaps.getPreviousTimeLap();
		String dateParam = dateFormat.format(lastTimeLap.getTime());

		String[] paramsForHMAC = (String[]) ArrayUtils.add(params, dateParam);

		String hmac = new StringBuffer(generateHMAC(password, paramsForHMAC)).append("O")
				.append(generateHMAC(password, params)).toString();

		logger.debug("Generated HMAC " + hmac + " for time lap " + lastTimeLap.getTime());

		return new OTP(password, hmac).generateChecksum();
	}

	/**
	 * Validates the password using the given hmac and params. Returns true if
	 * password is valid. False otherwise.
	 * 
	 * @param password
	 * @param providedHmac
	 * @param params
	 * @return
	 */
	public Result validatePasswordWithHmac(final OTP passwordWithMac, final String params[]) {
		boolean isValid = false;
		OTP otpWithoutChecksum = null;
		if (!passwordWithMac.hasValidChecksum()) {
			return new Result(Result.Code.FAIL_INVALID_CODE);
		} else {
			otpWithoutChecksum = passwordWithMac.stripChecksum();
		}

		// seperate the static and dynamic parts
		// 0 - dynamic part
		// 1 - static part
		String[] hmacToValidate = otpWithoutChecksum.getHmac().split("O");
		if (hmacToValidate.length != 2) {
			logger.debug("Invalid HMAC " + otpWithoutChecksum.getHmac());
			return new Result(Result.Code.FAIL_INVALID_CODE);
		}

		// determine the number units of time laps to validate
		final int timeLapPeriods = PASSWORD_EXPRIRY / TIME_LAP_INTERVAL;

		// get start time for valid time laps within the expiration time
		Calendar[] validTimes = timeLapGenerator.getPreviousTimeLap(timeLapPeriods);

		int counter = counterProvider.getCurrentValue();

		if (counter > MAX_ATTEMPTS) {
			return new Result(Result.Code.FAIL_MAX_ATTEMPTS_EXCEEDED);
		}

		logger.debug("Validating password within " + timeLapPeriods + " periods of " + validTimes[0].getTime());

		String[] paramsForHMAC = null;
		// validate password for all previous time periods within expiry period
		for (Calendar time : validTimes) {
			paramsForHMAC = (String[]) ArrayUtils.add(params, dateFormat.format(time.getTime()));
			if (validateHMAC(hmacToValidate[0], otpWithoutChecksum.getPassword(), paramsForHMAC)) {
				isValid = true;
				logger.debug("Found password valid for time lap " + time.getTime() + " and counter " + counter);
				counterProvider.reset();
				break;
			}
		}

		if (!isValid) {
			// increment the counter if provided mac is not valid
			counterProvider.getNextValue();

			// if the hmac does not belong to this user, throw invalid code
			if (!validateHMAC(hmacToValidate[1], otpWithoutChecksum.getPassword(), params)) {
				logger.debug("Codes swapped! Hmac does not belong to this user!");
				return new Result(Result.Code.FAIL_INVALID_CODE);
			}
			return new Result(Result.Code.FAIL_CODE_EXPIRED);
		}
		logger.debug("Validation Complete. Result is " + isValid);
		return new Result(Result.Code.SUCCESS);
	}

	/**
	 * Represents the results of OTP Validation.
	 * 
	 * @author aprasa2
	 *
	 */
	public static class Result {

		public static enum Code {
			SUCCESS, FAIL_INVALID_CODE, FAIL_CODE_EXPIRED, FAIL_MAX_ATTEMPTS_EXCEEDED
		}

		private Code resultCode;
		private String description;
		private String hmac;

		public Result(Code code) {
			this.resultCode = code;
		}

		public Result(Code code, String desc, String hmac) {
			this.resultCode = code;
			this.description = desc;
			this.hmac = hmac;
		}

		public Code getResultCode() {
			return resultCode;
		}

		public String getDescriptionc() {
			return description;
		}

		public String getHmac() {
			return hmac;
		}
	}

}
