package catdany.cryptocat.api;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CatDecryptor
{
	private final Cipher cipher;
	public final PrivateKey privateKey;
	
	/**
	 * Used to decrypt data using asymmetric cryptographic algorithms
	 * @param privateKey
	 * @param algorithm Encryption/Key algorithm, default is 'RSA'
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	public CatDecryptor(PrivateKey privateKey, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		this.privateKey = privateKey;
		this.cipher = Cipher.getInstance(algorithm);
	}
	
	/**
	 * Decrypt data coming from the stream<br>
	 * This method blocks until end of stream is reached
	 * @param stream Stream of data to decrypt
	 * @return Byte array containing decrypted data
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(InputStream stream) throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
	{
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = stream.read(buffer)) >= 0)
		{
			cipher.update(buffer, 0, len);
		}
		stream.close();
		return cipher.doFinal();
	}
	
	/**
	 * Decrypt data from the byte array
	 * @param data Byte array containing data to decrypt
	 * @return Byte array containing decrypted data
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * Decrypt file<br>
	 * This method uses {@link BufferedInputStream} with {@link FileInputStream}
	 * @param file File containing encrypted data
	 * @return Byte array containing decrypted data
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] decrypt(File file) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException
	{
		return decrypt(new BufferedInputStream(new FileInputStream(file)));
	}
}
