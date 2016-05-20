package catdany.cryptocat.api;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

public class CatKeyFactory
{
	/**
	 * Get public key object from its encoded form
	 * @throws KeyRestorationException A wrapper for {@link InvalidKeySpecException}, {@link NoSuchAlgorithmException}, {@link NoSuchProviderException}, {@link IllegalArgumentException}
	 * @param encoded
	 * @return
	 */
	public static PublicKey restorePublicKey(byte[] encoded)
	{
		try
		{
			KeyFactory keys = KeyFactory.getInstance("DSA", "SUN");
			return keys.generatePublic(new X509EncodedKeySpec(encoded));
		}
		catch (Exception t)
		{
			throw new KeyRestorationException(encoded, t);
		}
	}
	
	/**
	 * Get private key object from its encoded form
	 * @throws KeyRestorationException A wrapper for {@link InvalidKeySpecException}, {@link NoSuchAlgorithmException}, {@link NoSuchProviderException}, {@link IllegalArgumentException}
	 * @param encoded
	 * @return
	 */
	public static PrivateKey restorePrivateKey(byte[] encoded)
	{
		try
		{
			KeyFactory keys = KeyFactory.getInstance("DSA", "SUN");
			return keys.generatePrivate(new PKCS8EncodedKeySpec(encoded));
		}
		catch (Exception t)
		{
			throw new KeyRestorationException(encoded, t);
		}
	}
	
	public static class KeyRestorationException extends RuntimeException
	{
		/**
		 * 
		 */
		private static final long serialVersionUID = -2421332797739107097L;

		public KeyRestorationException(byte[] key, Throwable cause)
		{
			super(String.format("Could not restore a key: %s", DatatypeConverter.printHexBinary(key)), cause);
		}
	}
}