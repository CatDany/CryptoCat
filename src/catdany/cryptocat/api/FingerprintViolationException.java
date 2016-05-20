package catdany.cryptocat.api;

import javax.xml.bind.DatatypeConverter;

public class FingerprintViolationException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -5739650779239366721L;
	
	public FingerprintViolationException(String message, byte[] attemptedFingerprint, byte[] actualFingerprint)
	{
		super(String.format("%s. Given={%s} Actual={%s}", message, DatatypeConverter.printHexBinary(attemptedFingerprint), DatatypeConverter.printHexBinary(actualFingerprint)));
	}
}