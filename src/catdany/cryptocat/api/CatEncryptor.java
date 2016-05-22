package catdany.cryptocat.api;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CatEncryptor
{
	private final Cipher cipher;
	public final PublicKey publicKey;
	
	/**
	 * Used to encrypt data using asymmetric cryptographic algorithms
	 * @param publicKey
	 * @param algorithm Encryption/Key algorithm, default is 'RSA'
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	public CatEncryptor(PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		this.publicKey = publicKey;
		this.cipher = Cipher.getInstance(algorithm);
	}
	
	/**
	 * Encrypt data coming from the stream<br>
	 * This method blocks until end of stream is reached
	 * @param stream Stream of data to encrypt
	 * @return Byte array containing encrypted data
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] encrypt(InputStream stream) throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
	{
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
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
	 * Encrypt data from the byte array
	 * @param data Byte array containing data to encrypt
	 * @return Byte array containing encrypted data
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] encrypt(byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * Encrypt file<br>
	 * This method uses {@link BufferedInputStream} with {@link FileInputStream}
	 * @param file File containing data to encrypt
	 * @return Byte array containing encrypted data
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] encrypt(File file) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException
	{
		return encrypt(new BufferedInputStream(new FileInputStream(file)));
	}
}
