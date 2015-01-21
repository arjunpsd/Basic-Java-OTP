package org.arctix.security.hmac;

import java.util.Calendar;
import java.util.GregorianCalendar;

public class TimeLaps {

	int interval = 5; // number of units to roll in minutes

	// returns calendar to be used by this class
	//use the default instance
	private CalendarFactory factory = new DefaultCalendarFactory();

	/**
	 * Default constructor that creates timelaps with 5 minute intervals
	 */
	public TimeLaps() {

	}

	/**
	 * constructor that creates timelaps with the given interval
	 * 
	 * @param intervals
	 */
	public TimeLaps(int intervals) {
		this.interval = intervals;
	}

	/**
	 * For testing only allow using a different calendar factory
	 * 
	 * @param factory
	 */
	TimeLaps(CalendarFactory factory) {
		this.factory = factory;
	}

	/**
	 * Returns timelap for one interval
	 * 
	 * @return
	 */
	public Calendar getPreviousTimeLap() {
		return getPreviousTimeLap(1)[0];
	}

	/**
	 * Returns timelap for the given number of intervals.
	 * 
	 * @param n
	 * @return
	 */
	public Calendar[] getPreviousTimeLap(final int n) {
		Calendar[] timeLaps = new Calendar[n];
		Calendar now = factory.getInstance();

		now.set(Calendar.MILLISECOND, 0);
		now.set(Calendar.SECOND, 0);

		timeLaps[0] = now;
		int diff = (now.get(Calendar.MINUTE) % interval);
		timeLaps[0].add(Calendar.MINUTE, diff * -1);

		for (int i = 1; i < n; i++) {
			timeLaps[i] = new GregorianCalendar();
			timeLaps[i].setTimeInMillis(timeLaps[i - 1].getTimeInMillis());
			timeLaps[i].add(Calendar.MINUTE, interval * -1);
		}
		return timeLaps;
	}

	interface CalendarFactory {
		public Calendar getInstance();

	}

	private static class DefaultCalendarFactory implements CalendarFactory {

		@Override
		public Calendar getInstance() {
			return GregorianCalendar.getInstance();
		}

	}

}
