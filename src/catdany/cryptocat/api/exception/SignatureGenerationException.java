package catdany.cryptocat.api.exception;

/**
 * Used as a wrapper for any exceptions that may occur during signature generation
 * @author Dany
 *
 */
public class SignatureGenerationException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3563555000158528651L;

	public SignatureGenerationException(String message, Throwable t)
	{
		super(message, t);
	}
}