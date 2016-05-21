package catdany.cryptocat.api;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CatKeyGen
{
	public final PrivateKey privKey;
	public final PublicKey pubKey;
	
	/**
	 * @throws KeyGenException A wrapper for {@link NoSuchAlgorithmException}
	 * @param algorithmKeys Algorithm used for {@link KeyPairGenerator}, default is 'RSA'
	 * @param keySize Key size, default is '2048'
	 */
	public CatKeyGen(String algorithmKeys, int keySize)
	{
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithmKeys);
			keyGen.initialize(keySize);
			
			KeyPair pair = keyGen.generateKeyPair();
			this.privKey = pair.getPrivate();
			this.pubKey = pair.getPublic();
		}
		catch (NoSuchAlgorithmException t)
		{
			throw new KeyGenException(t);
		}
	}

	/**
	 * This exception is thrown when an error happens during {@link CatKeyGen#CatKeyGen(String, int) CatKeyGen construction}
	 * @author Dany
	 */
	public static class KeyGenException extends RuntimeException
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
}