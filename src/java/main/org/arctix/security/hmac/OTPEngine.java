package org.arctix.security.hmac;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.crypto.SecretKey;

import org.apache.commons.lang.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * One time password generator using HMAC validation. Generates a numeric
 * password and an associated HMAC that can be used for validating the password
 * later.
 * 
 * @author aprasa2
 *
 */
public class OTPEngine extends HMACEngine {

	private RandomNumberGenerator rngInstance = null;

	private final DateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmm");

	private final int TIME_LAP_INTERVAL = 5; // in minutes

	private final int PASSWORD_EXPRIRY = 15; // in minutes

	private static Logger logger = LoggerFactory.getLogger(OTPEngine.class);

	TimeLaps timeLapGenerator = new TimeLaps(TIME_LAP_INTERVAL);

	/**
	 * Parameterized constructor. Creates new instance of OTP Engine.
	 * Re-initializes Random Number generator.
	 * 
	 * @param key
	 * @param algorithm
	 */
	private OTPEngine(SecretKey key, String algorithm) {
		super(key, algorithm);
		if (rngInstance == null) {
			rngInstance = RandomNumberGenerator.getInstance();
		}
	}

	public static OTPEngine getInstance(SecretKey key) {
		return getInstance(key, "HmacSHA1");
	}

	public static OTPEngine getInstance(SecretKey key, String algorithm) {
		return new OTPEngine(key, algorithm);
	}

	/**
	 * Generates a one-time password based on the given parameter strings.
	 * 
	 * @param params
	 * @return
	 */
	public OTP generatePasswordWithHmac(String params[]) {

		// generate a random password
		String password = Integer.toString(rngInstance.getRandomInt());

		// Include start of last time lap as one of the parameters in generating
		// HMAC
		TimeLaps timeLaps = new TimeLaps(TIME_LAP_INTERVAL);
		Calendar lastTimeLap = timeLaps.getPreviousTimeLap();
		String dateParam = dateFormat.format(lastTimeLap.getTime());
		String[] paramsForHMAC = (String[]) ArrayUtils.add(params, dateParam);
		String hmac = generateHMAC(password, paramsForHMAC);
		logger.debug("Generated HMAC " + hmac + " for time lap " + lastTimeLap.getTime());
		return new OTP(password, hmac);
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
	public boolean validatePasswordWithHmac(OTP passwordWithMac, String params[]) {
		boolean isValid = false;

		// determine the number units of time laps to validate
		final int timeLapPeriods = PASSWORD_EXPRIRY / TIME_LAP_INTERVAL;

		// get start time for valid time laps within the expiration time
		Calendar[] validTimes = timeLapGenerator.getPreviousTimeLap(timeLapPeriods);

		logger.debug("Validating password within " + timeLapPeriods + " periods of " + validTimes[0].getTime());

		String[] paramsForHMAC = null;
		// validate password for all previous time periods within expiry period
		for (Calendar time : validTimes) {
			paramsForHMAC = (String[]) ArrayUtils.add(params, dateFormat.format(time.getTime()));
			if (validateHMAC(passwordWithMac.getHmac(), passwordWithMac.getPassword(), paramsForHMAC)) {
				isValid = true;
				logger.debug("Found password valid for time lap " + time.getTime());
				break;
			}
		}
		logger.debug("Validation Complete. Result is " + isValid);
		return isValid;
	}

}
