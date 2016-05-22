package catdany.cryptocat.api.exception;

import catdany.cryptocat.api.CatCipher;

/**
 * Used as a wrapper for any exceptions that may occur during encryption using {@link CatCipher}
 * @author Dany
 *
 */
public class CipherEncryptionException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3563555000158528651L;

	public CipherEncryptionException(String message, Throwable t)
	{
		super(message, t);
	}
}