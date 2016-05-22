package catdany.cryptocat.api;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import catdany.cryptocat.api.exception.KeyRestorationException;

public class CatKeyFactory
{
	/**
	 * Get public key object from its encoded form
	 * @throws KeyRestorationException A wrapper for {@link InvalidKeySpecException}, {@link NoSuchAlgorithmException}, {@link NoSuchProviderException}, {@link IllegalArgumentException}
	 * @param encoded
	 * @param algorithmKeys Algorithm used for {@link KeyFactory}, default is 'RSA'
	 * @return
	 */
	public static PublicKey restorePublicKey(byte[] encoded, String algorithmKeys)
	{
		try
		{
			KeyFactory factory = KeyFactory.getInstance(algorithmKeys);
			return factory.generatePublic(new X509EncodedKeySpec(encoded));
		}
		catch (Exception t)
		{
			throw new KeyRestorationException(encoded, algorithmKeys, t);
		}
	}
	
	/**
	 * Get private key object from its encoded form
	 * @throws KeyRestorationException A wrapper for {@link InvalidKeySpecException}, {@link NoSuchAlgorithmException}, {@link NoSuchProviderException}, {@link IllegalArgumentException}
	 * @param encoded
	 * @param algorithmKeys Algorithm used for {@link KeyFactory}, default is 'RSA'
	 * @return
	 */
	public static PrivateKey restorePrivateKey(byte[] encoded, String algorithmKeys)
	{
		try
		{
			KeyFactory factory = KeyFactory.getInstance(algorithmKeys);
			return factory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
		}
		catch (Exception t)
		{
			throw new KeyRestorationException(encoded, algorithmKeys, t);
		}
	}
}