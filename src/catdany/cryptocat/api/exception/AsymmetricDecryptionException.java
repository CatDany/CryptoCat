package catdany.cryptocat.api.exception;

import catdany.cryptocat.api.CatDecryptor;

/**
 * Used as a wrapper for any exceptions that may occur during decryption using {@link CatDecryptor}
 * @author Dany
 *
 */
public class AsymmetricDecryptionException extends SecurityException
{
	private static final long serialVersionUID = 5159459251241064715L;

	public AsymmetricDecryptionException(String message, Throwable t)
	{
		super(message, t);
	}
}
