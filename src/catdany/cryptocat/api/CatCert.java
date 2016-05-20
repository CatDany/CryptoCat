package catdany.cryptocat.api;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class CatCert
{
	static final Gson gson = new GsonBuilder().registerTypeAdapter(CatCert.class, new Serializer()).create();
	
	/**
	 * Certificate version<br>
	 * Default is 'V1'
	 */
	public final String version;
	
	public final String subject;
	public final Date validFrom;
	public final Date validTo;
	
	/**
	 * Certificate's public key
	 */
	public final PublicKey publicKey;
	
	/**
	 * Certificate's private key<br>
	 * Is <code>null</code> if it's public
	 */
	public final PrivateKey privateKey;
	
	/**
	 * This value is true if this certificate be a parent, and is this a Certificate Authority.
	 */
	public final boolean isCA;
	
	/**
	 * Certificate Authority that signed this certificate
	 */
	public final CatCert parent;
	
	/**
	 * Certificate fingerprint
	 */
	public final byte[] fingerprint;
	
	/**
	 * Fingerprint signed by the parent certificate<br>
	 * If parent is <code>null</code>, this certificate is self-signed
	 */
	public final byte[] signature;
	
	private CatCert(String version, String subject, Date validFrom, Date validTo, PublicKey publicKey, PrivateKey privateKey, boolean isCA, CatCert parent, byte[] fingerprint, byte[] signature)
	{
		this.version = version;
		this.subject = subject;
		this.validFrom = validFrom;
		this.validTo = validTo;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.isCA = isCA;
		this.parent = parent;
		this.fingerprint = fingerprint;
		this.signature = signature;
	}
	
	public static CatCert create(String version, String subject, Date validFrom, Date validTo, boolean isCA, CatCert parent)
	{
		CatKeyGen keys = new CatKeyGen();
		CatCert.Builder b = new CatCert.Builder()
			.setVersion(version)
			.setSubject(subject)
			.setValidFrom(validFrom)
			.setValidTo(validTo)
			.setIsCA(isCA)
			.setPublicKey(keys.pubKey)
			.setPrivateKey(keys.privKey)
			.setParent(parent)
			.setFingerprint();
		PrivateKey privKey = (parent == null) ? b.privateKey : parent.privateKey;
		try
		{
			CatSigner sig = new CatSigner(privKey);
			b.setSignature(sig.sign(b.fingerprint));
		}
		catch (Exception t)
		{
			new RuntimeException(t);
		}
		return b.build();
	}
	
	@Override
	public String toString()
	{
		return CatCert.toJson(this);
	}
	
	/**
	 * Clone this object without {@link #privateKey}
	 * @return
	 */
	public CatCert clonePublic()
	{
		return new CatCert(version, subject, validFrom, validTo, publicKey, null, isCA, parent, fingerprint, signature);
	}
	
	/**
	 * Generate a certificate's fingerprint<br>
	 * Fingerprint is the hash of a serialized certificate (fingerprint and signature values are not serialized)
	 * @return
	 */
	public byte[] fingerprint()
	{
		CatCert cert = new CatCert(version, subject, validFrom, validTo, publicKey, null, isCA, parent, null, null);
		try
		{
			return MessageDigest.getInstance("SHA-1").digest(toJson(cert).getBytes(Charset.forName("ISO-8859-15")));
		}
		catch (NoSuchAlgorithmException t)
		{
			throw new RuntimeException("SHA-1 is not a valid hashing algorithm.", t);
		}
	}
	
	/**
	 * Check if the certificate is expired
	 * @return <code>true</code> if {@link #validFrom} < NOW < {link #validTo}
	 */
	public boolean isExpired()
	{
		Date date = CatUtils.now();
		return date.after(validFrom) && date.before(validTo);
	}
	
	public static String toJson(CatCert cert)
	{
		return gson.toJson(cert);
	}
	
	public static CatCert fromJson(String json)
	{
		return gson.fromJson(json, CatCert.class);
	}
	
	/**
	 * @throws RuntimeException - A wrapper for {@link IOException}
	 * @param file
	 * @return
	 */
	public static CatCert fromJson(File file)
	{
		try
		{
			return gson.fromJson(new FileReader(file), CatCert.class);
		}
		catch (IOException t)
		{
			throw new RuntimeException("Couldn't read certificate from file", t);
		}
	}
	
	public static class Builder
	{
		private String version = "V1";
		private String subject = null;
		private Date validFrom = new Date(0);
		private Date validTo = new Date(0);
		private PublicKey publicKey = null;
		private PrivateKey privateKey = null;
		private boolean isCA = false;
		private CatCert parent = null;
		private byte[] fingerprint = null;
		private byte[] signature = null;
		
		public Builder() {}
		
		/**
		 * Set certificate version, default is 'V1'
		 * @param version
		 */
		public Builder setVersion(String version)
		{
			this.version = version;
			return this;
		}
		
		/**
		 * Set subject, who owns the certificate, default is null
		 * @param subject
		 */
		public Builder setSubject(String subject)
		{
			this.subject = subject;
			return this;
		}
		
		/**
		 * Set the date from which the certificate is valid, default is <code>Date(0)</code>
		 * @param validFrom
		 */
		public Builder setValidFrom(Date validFrom)
		{
			this.validFrom = validFrom;
			return this;
		}
		
		/**
		 * Set the date from which the certificate is valid, default is <code>Date(0)</code>
		 * @param validFrom
		 */
		public Builder setValidTo(Date validTo)
		{
			this.validTo = validTo;
			return this;
		}
		
		/**
		 * Set public key of the certificate, a required argument
		 * @param publicKey
		 */
		public Builder setPublicKey(PublicKey publicKey)
		{
			this.publicKey = publicKey;
			return this;
		}
		/**
		 * Set private key of the certificate, default is <code>null</code>
		 * @param publicKey
		 */
		public Builder setPrivateKey(PrivateKey privateKey)
		{
			this.privateKey = privateKey;
			return this;
		}
		
		/**
		 * <code>true</code> if this is a Certificate Authority and can sign other certificates
		 * @param isCA
		 */
		public Builder setIsCA(boolean isCA)
		{
			this.isCA = isCA;
			return this;
		}
		
		/**
		 * Set certificate fingerprint
		 * @param fingerprint
		 */
		public Builder setFingerprint(byte[] fingerprint)
		{
			this.fingerprint = fingerprint;
			return this;
		}
		
		/**
		 * Generate certificate fingerprint and set it
		 * @see Builder#fingerprint()
		 * @return
		 */
		public Builder setFingerprint()
		{
			this.fingerprint = fingerprint();
			return this;
		}
		
		/**
		 * Set signature, fingerprint signed by the parent certificate
		 * @param signature
		 */
		public Builder setSignature(byte[] signature)
		{
			this.signature = signature;
			return this;
		}
		
		/**
		 * Set parent certificate
		 * @param parent
		 * @throws IllegalArgumentException If the parent is not a Certificate Authority (parent.{@link #isCA})
		 * @return
		 */
		public Builder setParent(CatCert parent)
		{
			if (parent != null && !parent.isCA)
			{
				throw new IllegalArgumentException("Attempted to set a parent certificate that is not a CA.");
			}
			if (parent != null && parent.privateKey != null)
			{
				parent = new CatCert(parent.version, parent.subject, parent.validFrom, parent.validTo, parent.publicKey, null, parent.isCA, parent.parent, parent.fingerprint, parent.signature);
			}
			this.parent = parent;
			return this;
		}
		
		/**
		 * Generate a fingerprint for this builder
		 * @return
		 */
		public byte[] fingerprint()
		{
			if (subject == null) throw new IllegalArgumentException("Attempted to build a certificate with no subject.");
			if (publicKey == null) throw new IllegalArgumentException("Attempted to build a certificate with no public key.");
			CatCert cert = new CatCert(version, subject, validFrom, validTo, publicKey, privateKey, isCA, parent, fingerprint, signature);
			return cert.fingerprint();
		}
		
		/**
		 * Build a certificate object
		 * @return
		 * @throws IllegalArgumentException if any of the required values aren't specified<br>
		 */
		public CatCert build()
		{
			if (fingerprint == null) throw new IllegalArgumentException("Attempted to build a certificate with no fingerprint.");
			if (signature == null) throw new IllegalArgumentException("Attempted to build a certificate with no signature.");
			byte[] actualFingerprint = fingerprint();
			if (!Arrays.equals(actualFingerprint, fingerprint)) throw new FingerprintViolationException("Attempted to build a certificate with invalid fingerprint", fingerprint, actualFingerprint);
			CatVerifier ver = new CatVerifier(parent == null ? publicKey : parent.publicKey);
			try
			{
				if (!ver.verify(fingerprint, signature)) throw new IllegalSignatureException("Attempted to build a certificate with invalid signature", signature);
			}
			catch (InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | IOException t)
			{
				throw new RuntimeException(t);
			}
			return new CatCert(version, subject, validFrom, validTo, publicKey, privateKey, isCA, parent, fingerprint, signature);
		}
	}
	
	public static class Serializer implements JsonSerializer<CatCert>, JsonDeserializer<CatCert>
	{
		private Serializer() {}
		
		@Override
		public JsonElement serialize(CatCert cert, Type type, JsonSerializationContext context)
		{
			JsonObject json = new JsonObject();
			json.addProperty("Version", cert.version);
			json.addProperty("Subject", cert.subject);
			json.addProperty("ValidFrom", CatUtils.formatDate(cert.validFrom));
			json.addProperty("ValidTo", CatUtils.formatDate(cert.validTo));
			json.addProperty("IsCA", cert.isCA);
			if (cert.fingerprint != null)
			{
				json.addProperty("Fingerprint", DatatypeConverter.printHexBinary(cert.fingerprint));
			}
			if (cert.signature != null)
			{
				json.addProperty("Signature", DatatypeConverter.printHexBinary(cert.signature));
			}
			json.addProperty("PublicKey", DatatypeConverter.printHexBinary(cert.publicKey.getEncoded()));
			if (cert.privateKey != null)
			{
				json.addProperty("PrivateKey", DatatypeConverter.printHexBinary(cert.privateKey.getEncoded()));
			}
			if (cert.parent != null)
			{
				json.add("Parent", gson.toJsonTree(cert.parent));
			}
			return json;
		}
		
		@Override
		public CatCert deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context) throws JsonParseException
		{
			JsonObject json = jsonElement.getAsJsonObject();
			CatCert.Builder b = new CatCert.Builder()
				.setVersion(json.get("Version").getAsString())
				.setSubject(json.get("Subject").getAsString())
				.setIsCA(json.get("IsCA").getAsBoolean())
				.setFingerprint(DatatypeConverter.parseHexBinary(json.get("Fingerprint").getAsString()))
				.setSignature(DatatypeConverter.parseHexBinary(json.get("Signature").getAsString()))
				.setPublicKey(CatKeyFactory.restorePublicKey(DatatypeConverter.parseHexBinary(json.get("PublicKey").getAsString())));
			try
			{
				b
					.setValidFrom(CatUtils.parseDate(json.get("ValidFrom").getAsString()))
					.setValidTo(CatUtils.parseDate(json.get("ValidTo").getAsString()));
			}
			catch (ParseException t)
			{
				throw new RuntimeException("Couldn't parse ValidFrom / ValidTo date.", t);
			}
			if (json.has("PrivateKey"))
			{
				b.setPrivateKey(CatKeyFactory.restorePrivateKey(DatatypeConverter.parseHexBinary(json.get("PrivateKey").getAsString())));
			}
			if (json.has("Parent"))
			{
				b.setParent(fromJson(json.get("Parent").toString()));
			}
			return b.build();
		}
	}
}