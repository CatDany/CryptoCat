package catdany.cryptocat.api.exception;

import java.io.IOException;

/**
 * Used as a wrapper for {@link IOException}
 * @author Dany
 *
 */
public class RuntimeIOException extends RuntimeException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3474121565676237706L;

	public RuntimeIOException(IOException t)
	{
		super(t);
	}
}