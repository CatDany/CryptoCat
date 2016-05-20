package catdany.cryptocat.api;

import javax.xml.bind.DatatypeConverter;

public class IllegalSignatureException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -1008595579674378960L;

	public IllegalSignatureException(String message, byte[] signature)
	{
		super(String.format("%s. Signature={%s}", message, DatatypeConverter.printHexBinary(signature)));
	}
}