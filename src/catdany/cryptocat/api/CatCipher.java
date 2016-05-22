package catdany.cryptocat.api;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class CatCipher
{
	private final SecretKey secret;
	private final Cipher cipher;
	
	/**
	 * Used for encrypting data with DES cipher
	 * @param password
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 */
	public CatCipher(byte[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
	{
		if (password.length != 8)
		{
			throw new IndexOutOfBoundsException("Password must be 8 bytes long.");
		}
		DESKeySpec keySpec = new DESKeySpec(password);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
		secret = factory.generateSecret(keySpec);
		this.cipher = Cipher.getInstance("DES");
	}
	
	/**
	 * Encrypt data with a password
	 * @param data
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] encrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
	{
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		return cipher.doFinal(data);
	}
	
	/**
	 * Decrypt data with a password
	 * @param encrypted
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 */
	public byte[] decrypt(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
	{
		cipher.init(Cipher.DECRYPT_MODE, secret);
		return cipher.doFinal(encrypted);
	}
}