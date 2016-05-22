package catdany.cryptocat.api.exception;

import catdany.cryptocat.api.CatCipher;

/**
 * Used as a wrapper for any exceptions that may occur during decryption using {@link CatCipher}
 * @author Dany
 *
 */
public class CipherDecryptionException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3563555000158528651L;

	public CipherDecryptionException(String message, Throwable t)
	{
		super(message, t);
	}
}