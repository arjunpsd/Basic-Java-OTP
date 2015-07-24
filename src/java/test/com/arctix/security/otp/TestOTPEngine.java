package com.arctix.security.otp;

import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import com.arctix.security.otp.OTP;
import com.arctix.security.otp.OTPEngine;
import com.arctix.security.otp.TimeLaps;
import com.arctix.security.otp.OTPEngine.Result;

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
		assertEquals(Result.Code.SUCCESS, engine.validatePasswordWithHmac(otp, params).getResultCode());
	}

	@Test
	public void testOTPEngine_1To10MinDelay_Success() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);

		// validate password in i minutes into future
		for (int i = 1; i < 11; i++) {
			engine.timeLapGenerator = getTimeLapFromFuture(i);
			assertEquals("At " + i, Result.Code.SUCCESS, engine.validatePasswordWithHmac(otp, params).getResultCode());
		}
	}
	
	@Test
	public void testOTPEngine_NthAttempt_Success() {

		OTPEngine generationEngine = OTPEngine.getInstance(key);
		
		OTPEngine validationEngine = OTPEngine.getInstance(key);
		
		// generate password NOW
		OTP otp = generationEngine.generatePasswordWithHmac(params);
		
		OTP wrongPassword = new OTP("1234", otp.getHmac());
		// validate password in i minutes into future
		for (int i = 1; i < 6; i++) {
			validationEngine.timeLapGenerator = getTimeLapFromFuture(i);
			assertEquals("At " + i, Result.Code.FAIL_INVALID_CODE, validationEngine.validatePasswordWithHmac(wrongPassword, params).getResultCode());
		}
		assertEquals("At Last", Result.Code.SUCCESS, validationEngine.validatePasswordWithHmac(otp, params).getResultCode());
	}

	
	@Test
	public void testOTPEngine_GreaterThan14_Fail() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);

		// validate password in i minutes into future
		for (int i = 15; i < 30; i++) {
			engine.timeLapGenerator = getTimeLapFromFuture(i);
			if((i - 15) > OTPEngine.MAX_ATTEMPTS){
				assertEquals("At " + i, Result.Code.FAIL_MAX_ATTEMPTS_EXCEEDED, engine.validatePasswordWithHmac(otp, params).getResultCode());	
			} else {
				assertEquals("At " + i, Result.Code.FAIL_CODE_EXPIRED, engine.validatePasswordWithHmac(otp, params).getResultCode());
			}
		}
	}
	
	@Test
	public void testOTPEngine_InvalidHMAC() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp = engine.generatePasswordWithHmac(params);
		otp.hmac = "93842394p238np23";

		assertEquals(Result.Code.FAIL_INVALID_CODE, engine.validatePasswordWithHmac(otp, params).getResultCode());	

	}
	
	@Test
	public void testOTPEngine_SwappedCode() {

		OTPEngine engine = OTPEngine.getInstance(key);

		// generate password NOW
		OTP otp1 = engine.generatePasswordWithHmac(params);
		
		String[] anotherParam = {"98765432100"};
		
		// generate password NOW
		OTP otp2 = engine.generatePasswordWithHmac(anotherParam);

		//assign some elses password
		otp1.password = otp2.getPassword();

		assertEquals(Result.Code.FAIL_INVALID_CODE, engine.validatePasswordWithHmac(otp1, params).getResultCode());	

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
