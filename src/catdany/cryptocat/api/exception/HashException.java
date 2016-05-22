package catdany.cryptocat.api.exception;

/**
 * Used as a wrapper for any exceptions that may occur during hashing
 * @author Dany
 *
 */
public class HashException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3563555000158528651L;

	public HashException(String message, Throwable t)
	{
		super(message, t);
	}
}