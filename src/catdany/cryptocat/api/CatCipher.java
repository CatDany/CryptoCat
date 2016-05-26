package catdany.cryptocat.api;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

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
	public final byte padding;
	
	/**
	 * Used for encrypting data with DES cipher
	 * @param password
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 */
	public CatCipher(byte[] password, byte padding) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
	{
		this.padding = padding;
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
	 * Encrypt data with a password<br>
	 * {@link #padding} bytes are added to the end of the byte array.
	 * @param data
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] encrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
	{
		int requiredPadding = (8 - data.length % 8) % 8;
		byte[] paddedData = new byte[data.length + requiredPadding];
		for (int i = 0; i < data.length; i++)
		{
			paddedData[i] = data[i]; 
		}
		for (int i = data.length; i < paddedData.length; i++)
		{
			paddedData[i] = padding;
		}
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		return cipher.doFinal(paddedData);
	}
	
	/**
	 * Decrypt data with a password<br>
	 * Remove all {@link #padding} in the end of the byte array.
	 * @param encrypted
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 */
	public byte[] decrypt(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
	{
		cipher.init(Cipher.DECRYPT_MODE, secret);
		byte[] data = cipher.doFinal(encrypted);
		return removePadding(data);
	}
	
	private byte[] removePadding(byte[] data)
	{
		int last = data.length;
		for (int i = last - 1; i > 0; i--)
		{
			if (data[i] != padding)
			{
				break;
			}
			last = i;
		}
		return Arrays.copyOfRange(data, 0, last);
	}
}