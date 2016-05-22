package catdany.cryptocat.api;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import catdany.cryptocat.api.exception.CertificateExpiredException;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

public class CatZipper
{
	private final File fileToSign;
	private final File tmpSig;
	private final File outputZip;
	public final CatSignature sig;
	
	/**
	 * Sign a file and create temporary files needed for zipping<br>
	 * To create a zip-file, call {@link #zip()}
	 * @param zipFile
	 * @param cert Certificate with a private key
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public CatZipper(File fileToSign, File outputZip, CatCert cert) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException
	{
		if (!cert.isExpired()) throw new CertificateExpiredException(cert);
		this.fileToSign = fileToSign;
		this.outputZip = outputZip;
		CatSignature sigTmp = new CatSignature(new CatSigner(cert.privateKey).sign(fileToSign, cert.algorithmSignatureHash), cert, fileToSign.getName(), null);
		CatTimestamp timestamp = CatTimestamp.generate(sigTmp);
		this.sig = new CatSignature(sigTmp.signedBytes, sigTmp.cert, sigTmp.filename, timestamp);
		File tmpFolder = new File(System.getenv("TEMP") + "\\" + Math.random());
		if (!tmpFolder.exists() || !tmpFolder.isDirectory())
		{
			tmpFolder.mkdir();
		}
		tmpSig = new File(tmpFolder, "signature.json");
		tmpSig.createNewFile();
		FileWriter writer = new FileWriter(tmpSig);
		CatSignature.gson.toJson(sig, writer);
		writer.close();
	}
	
	/**
	 * Create a zip-file for temporary files
	 * @throws ZipException
	 * @throws IOException
	 */
	public void zip() throws ZipException, IOException
	{
		if (outputZip.exists() && !outputZip.isDirectory())
		{
			outputZip.delete();
		}
		ZipFile zip = new ZipFile(outputZip);
		ZipParameters params = new ZipParameters();
		params.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
		params.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_NORMAL);
		zip.addFile(tmpSig, params);
		zip.addFile(fileToSign, params);
		tmpSig.delete();
	}
}