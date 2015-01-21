# Basic OTP Generator/Validator
A simple One-Time-Password generator and validator. An OTP is typically used in two-factor authentication, where the password is sent to a user via known email or phone number, which is then entered back on a site and validated, confirming the identity of the user.

OTPGenerator generates a random numeric password and corresponding HMAC using a secret key. Additional parameters may be added while generating HMAC. The password is sent to a secondary device considered 'pre-authenticated' and the HMAC is sent to the device requesting authentication. During the validation step, the user provided password and HMAC from earlier step is passed to the OTP Engine for validation. A wrong password results in mismatch of HMAC and therefore considered invalid.

<h2>Usage Guide</h2>

<h3>Steps to Generate a One-Time-Password</h3>
1. Create an instance of OTPEngine, passing in a secret key

	OTPEngine engine = OTPEngine.getInstance(secretKey);
	
2. Optionally, add some extra parameters to make the password/hmac combination unique to the user/instance

	String params = new String[] { "CUSTOMERID-12345" };
	
3. Generate the password by calling the 'generatePasswordWithHmac' method on the OTP engine and passing in the extra parameters
	
	OTP otp = engine.generatePasswordWithHmac(params);
	
4. The returned object contains two properties<br>
	<i>password</i> - contains the generated random numeric password. The password is sent via secure means to the user's email or phone<br>
	<i>hmac</i> - Hashed message authentication code associated with this password. HMAC value is returned to the front-end requesting the OTP and entered back along with the password during the validation step.
	

<h3>Steps to Validate One-Time-Password</h3>
1. Create an instance of OTPEngine, passing in the same secret key used while generating the password. <i>If the key is different from the one used for generating the password, it cannot be validated!</i>

	OTPEngine engine = OTPEngine.getInstance(key);

2. Validate the password using the 'validatePasswordWithHmac' method on the engine, passing in the password and hmac received from the front-end/user interface.
	
	boolean isValid = engine.validatePasswordWithHmac(new OTP(password, hmac), params);
	if(isValid){
		//hooray!!
	} else {
		//fail!!
	}
	
3. By default, generated password is valid for 10-15 minutes from the time it is generated. 
	




	
	


