package catdany.cryptocat.api.exception;

/**
 * Used as a wrapper for any exceptions that may occur during signature verification
 * @author Dany
 *
 */
public class SignatureVerificationException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3563555000158528651L;

	public SignatureVerificationException(String message, Throwable t)
	{
		super(message, t);
	}
}