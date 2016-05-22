package catdany.cryptocat.api.exception;

import javax.xml.bind.DatatypeConverter;

import catdany.cryptocat.api.CatKeyFactory;

/**
 * This exception is thrown when an error happens on {@link CatKeyFactory#restorePublicKey(byte[], String)} or {@link CatKeyFactory#restorePrivateKey(byte[], String)}
 * @author Dany
 */
public class KeyRestorationException extends RuntimeException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -2421332797739107097L;

	public KeyRestorationException(byte[] key, String algorithm, Throwable cause)
	{
		super(String.format("Could not restore %s key: %s", algorithm, DatatypeConverter.printHexBinary(key)), cause);
	}
}