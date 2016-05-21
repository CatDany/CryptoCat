package catdany.cryptocat.api;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class CatVerifier
{
	private final PublicKey publicKey;
	
	public CatVerifier(PublicKey publicKey)
	{
		this.publicKey = publicKey;
	}
	
	/**
	 * Verify a signature<br>
	 * This method blocks until end of stream is reached
	 * @param stream Stream of original bytes
	 * @param signedBytes Byte array containing a signature
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	public boolean verify(InputStream stream, byte[] signedBytes, String algorithmSignatureHash) throws SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException
	{
		Signature dsa = Signature.getInstance(algorithmSignatureHash);
		dsa.initVerify(publicKey);
		
		byte[] buffer = new byte[1024];
		int len;
		while (stream.available() != 0)
		{
			len = stream.read(buffer);
			dsa.update(buffer, 0, len);
		}
		stream.close();
		
		return dsa.verify(signedBytes);
	}

	/**
	 * Verify a signature<br>
	 * This method uses {@link BufferedInputStream} with {@link FileInputStream}
	 * @param file File containing original data
	 * @param signedBytes Byte array containing a signature
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	public boolean verify(File file, byte[] signedBytes, String algorithmSignatureHash) throws InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException
	{
		return verify(new BufferedInputStream(new FileInputStream(file)), signedBytes, algorithmSignatureHash);
	}

	/**
	 * Verify a signature<br>
	 * This method blocks until end of stream is reached
	 * @param data Byte array containing original data
	 * @param signedBytes Byte array containing a signature
	 * @param algorithmSignatureHash Algorithm used for {@link Signature}, default is 'SHA256withRSA'
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	public boolean verify(byte[] data, byte[] signedBytes, String algorithmSignatureHash) throws InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, IOException
	{
		return verify(new ByteArrayInputStream(data), signedBytes, algorithmSignatureHash);
	}
}