package catdany.cryptocat.api;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class CatSigner
{
	private final PrivateKey privateKey;
	
	public CatSigner(PrivateKey privateKey)
	{
		this.privateKey = privateKey;
	}
	
	/**
	 * Sign bytes coming from the stream<br>
	 * This method blocks until end of stream is reached
	 * @param stream Stream of bytes to sign
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return Byte array containing a signature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public byte[] sign(InputStream stream, String algorithmSignatureHash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException
	{
		Signature sig = Signature.getInstance(algorithmSignatureHash);
		sig.initSign(privateKey);
		
		byte[] buffer = new byte[1024];
		int len;
		while ((len = stream.read(buffer)) >= 0)
		{
			sig.update(buffer, 0, len);;
		}
		stream.close();
		return sig.sign();
	}

	/**
	 * Sign byte array
	 * @param bytes Byte array to sign
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return Byte array containing a signature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public byte[] sign(byte[] bytes, String algorithmSignatureHash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException
	{
		return sign(new ByteArrayInputStream(bytes), algorithmSignatureHash);
	}

	/**
	 * Sign a file<br>
	 * This method uses {@link BufferedInputStream} of {@link FileInputStream}
	 * @param file File to sign
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return Byte array containing a signature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public byte[] sign(File file, String algorithmSignatureHash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException
	{
		return sign(new BufferedInputStream(new FileInputStream(file)), algorithmSignatureHash);
	}
}