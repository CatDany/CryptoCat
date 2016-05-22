package catdany.cryptocat.api.exception;

import catdany.cryptocat.api.CatKeyGen;

/**
 * This exception is thrown when an error happens during {@link CatKeyGen#CatKeyGen(String, int) CatKeyGen construction}
 * @author Dany
 */
public class KeyGenException extends RuntimeException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -6432673686381331016L;

	public KeyGenException(Throwable t)
	{
		super(t);
	}
}