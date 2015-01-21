package org.arctix.security.hmac;

import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.arctix.security.hmac.OTP;
import org.arctix.security.hmac.OTPEngine;
import org.arctix.security.hmac.TimeLaps;
import org.junit.Before;
import org.junit.Test;

import junit.framework.TestCase;

public class TestOTPEngine extends TestCase {
	private SecretKey key = null;
	private String[] params = null;

	@Before
	public void setUp() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		key = keyGen.generateKey();
		params = new String[] { "0010000123434343" };

	}

	@Test
	public void testOTPEngine_ZeroDelay() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);

		// validate immediately
		assertTrue(engine.validatePasswordWithHmac(otp, params));
	}

	@Test
	public void testOTPEngine_1To10MinDelay_Success() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);

		// validate password in i minutes into future
		for (int i = 1; i < 11; i++) {
			engine.timeLapGenerator = getTimeLapFromFuture(i);
			assertTrue("At " + i, engine.validatePasswordWithHmac(otp, params));
		}
	}

	
	@Test
	public void testOTPEngine_GreaterThan14_Fail() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);

		// validate password in i minutes into future
		for (int i = 15; i < 30; i++) {
			engine.timeLapGenerator = getTimeLapFromFuture(i);
			assertFalse("At " + i, engine.validatePasswordWithHmac(otp, params));
		}
	}

	private TimeLaps getTimeLapFromFuture(final int minutesIntoFuture) {
		return new TimeLaps(new TimeLaps.CalendarFactory() {
			@Override
			public Calendar getInstance() {
				Calendar calendar = GregorianCalendar.getInstance();
				calendar.add(Calendar.MINUTE, minutesIntoFuture);
				return calendar;
			}
		});
	}

}
