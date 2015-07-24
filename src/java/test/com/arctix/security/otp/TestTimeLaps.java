package com.arctix.security.otp;

import java.util.Calendar;
import java.util.GregorianCalendar;

import org.junit.Test;

import com.arctix.security.otp.TimeLaps;

import junit.framework.TestCase;

public class TestTimeLaps extends TestCase {
	@Test
	public void testOneTimeLaps() {
		TimeLaps laps = new TimeLaps();
		Calendar timeNow = GregorianCalendar.getInstance();
		int diff = timeNow.get(Calendar.MINUTE) % 5;
		timeNow.add(Calendar.MINUTE, diff * -1);
		assertEquals(timeNow.get(Calendar.MINUTE), laps.getPreviousTimeLap().get(Calendar.MINUTE));
	}

	@Test
	public void testMultipleTimeLaps() {
		TimeLaps timeLaps = new TimeLaps();
		int n = 5;
		Calendar[] laps = timeLaps.getPreviousTimeLap(n);

		assertNotNull(timeLaps.getPreviousTimeLap());
		assertEquals(n, laps.length);

		for (int i = 1; i < n; i++) {
			assertNotNull(laps[i - 1].getTime());
			assertNotNull(laps[i].getTime());
			//convert 60 to 0
			long toBe = laps[i].get(Calendar.MINUTE) == 55 ? 0 : laps[i].get(Calendar.MINUTE) + 5;			
			assertEquals(laps[i - 1].get(Calendar.MINUTE), toBe);
		}

	}

}
