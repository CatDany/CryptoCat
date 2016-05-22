package catdany.cryptocat.api.exception;

import catdany.cryptocat.api.CatEncryptor;

/**
 * Used as a wrapper for any exceptions that may occur during encryption using {@link CatEncryptor}
 * @author Dany
 *
 */
public class AsymmetricEncryptionException extends SecurityException
{
	private static final long serialVersionUID = 5159459251241064715L;

	public AsymmetricEncryptionException(String message, Throwable t)
	{
		super(message, t);
	}
}
