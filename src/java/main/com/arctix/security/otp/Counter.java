package com.arctix.security.otp;

/**
 * Interface for multiple counter providers. Implementation could be in-memory
 * providers for single server deployments to databsae providers for cluster
 * deployments.
 * 
 * @author aprasa2
 *
 */
public interface Counter {
	
	/**
	 * Return current value of counter
	 * @return
	 */
	public int getCurrentValue();

	/**
	 * Get next value in sequence of counter.
	 * @return
	 */
	public int getNextValue();
	
	/**
	 * Reset counter value to zero.
	 * @return
	 */
	public int reset();
}
