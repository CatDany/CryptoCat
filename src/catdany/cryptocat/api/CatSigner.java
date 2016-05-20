package catdany.cryptocat.api;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
	
	public byte[] sign(InputStream stream) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException
	{
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		dsa.initSign(privateKey);
		
		byte[] buffer = new byte[1024];
		int len;
		while ((len = stream.read(buffer)) >= 0)
		{
			dsa.update(buffer, 0, len);;
		}
		stream.close();
		return dsa.sign();
	}
	
	public byte[] sign(byte[] bytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException
	{
		return sign(new ByteArrayInputStream(bytes));
	}
	
	public byte[] sign(File file) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException
	{
		return sign(new BufferedInputStream(new FileInputStream(file)));
	}
}