package catdany.cryptocat.api;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CatKeyGen
{
	public final PrivateKey privKey;
	public final PublicKey pubKey;
	
	/**
	 * @throws KeyGenException A wrapper for {@link NoSuchAlgorithmException}, {@link NoSuchProviderException}
	 */
	public CatKeyGen()
	{
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			keyGen.initialize(1024);
			
			KeyPair pair = keyGen.generateKeyPair();
			this.privKey = pair.getPrivate();
			this.pubKey = pair.getPublic();
		}
		catch (NoSuchProviderException | NoSuchAlgorithmException t)
		{
			throw new KeyGenException(t);
		}
	}
	
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