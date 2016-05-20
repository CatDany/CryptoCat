package catdany.cryptocat.api;

import javax.xml.bind.DatatypeConverter;

public class CertificateExpiredException extends SecurityException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1815947682405132491L;

	public CertificateExpiredException(CatCert cert)
	{
		super(String.format("Attempted to use a certificate which is either expired or not yet valid. Subject: %s | Valid From: %s | Valid To: %s | Fingerprint: %s", cert.subject, CatUtils.formatDate(cert.validFrom), CatUtils.formatDate(cert.validTo), DatatypeConverter.printHexBinary(cert.fingerprint)));
	}
}