package catdany.cryptocat.api;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import catdany.cryptocat.api.exception.KeyGenException;

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
}