package com.arctix.security.otp;

public class InMemoryCounter implements Counter {

	private int counter = 0;

	@Override
	public int getCurrentValue() {
		return counter;
	}

	@Override
	public int getNextValue() {
		return ++counter;
	}

	@Override
	public int reset() {
		counter = 0;
		return counter;
	}

}
