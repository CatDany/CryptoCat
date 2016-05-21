package catdany.cryptocat.api;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;

public class CatUnzipper
{
	public final CatSignature sig;
	public final File tmpFile;
	
	/**
	 * Temporarily extract signed zip-file (signed file and signature)<br>
	 * Directory for temporary files: %TEMP%/<code>tempDir</code>_<i>(random)</i>
	 * @param zipFile
	 * @param tempDir
	 */
	public CatUnzipper(File zipFile) throws IOException, ZipException
	{
		ZipFile zip = new ZipFile(zipFile);
		File tmpFolder = new File(System.getenv("TEMP") + "\\" + Math.random());
		if (!tmpFolder.exists() || !tmpFolder.isDirectory())
		{
			tmpFolder.mkdir();
		}
		File tmpSignature = new File(tmpFolder, "signature.json");
		zip.extractFile("signature.json", tmpFolder.getPath());
		sig = CatSignature.fromJson(tmpSignature);
		tmpFile = new File(tmpFolder, sig.filename);
		zip.extractFile(sig.filename, tmpFolder.getPath());
	}
	
	/**
	 * Verify
	 * @return
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public boolean verify() throws InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException
	{
		CatVerifier ver = new CatVerifier(sig.cert.publicKey);
		return ver.verify(tmpFile, sig.signedBytes, sig.cert.algorithmSignatureHash);
	}
}