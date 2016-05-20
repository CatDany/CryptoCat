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
import java.security.NoSuchProviderException;
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
	
	public boolean verify(InputStream stream, byte[] signedBytes) throws SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException
	{
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
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
	
	public boolean verify(File file, byte[] signedBytes) throws InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException
	{
		return verify(new BufferedInputStream(new FileInputStream(file)), signedBytes);
	}
	
	public boolean verify(byte[] data, byte[] signedBytes) throws InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return verify(new ByteArrayInputStream(data), signedBytes);
	}
}