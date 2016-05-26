package catdany.cryptocat.api;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import catdany.cryptocat.api.CatUtils.RuntimeParseException;
import catdany.cryptocat.api.exception.CipherDecryptionException;
import catdany.cryptocat.api.exception.CipherEncryptionException;
import catdany.cryptocat.api.exception.FingerprintViolationException;
import catdany.cryptocat.api.exception.HashException;
import catdany.cryptocat.api.exception.IllegalSignatureException;
import catdany.cryptocat.api.exception.SignatureGenerationException;
import catdany.cryptocat.api.exception.SignatureVerificationException;

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
	public final String note;
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
	
	/**
	 * Fingerprint algorithm<br>
	 * Default is 'SHA-1'
	 */
	public final String algorithmFingerprint;
	/**
	 * PKC algorithm<br>
	 * Default is 'RSA'
	 */
	public final String algorithmKeys;
	/**
	 * Signature hashing algorithm<br>
	 * Default is 'SHA256withRSA'
	 */
	public final String algorithmSignatureHash;
	
	private CatCert(String version, String subject, String note, Date validFrom, Date validTo, PublicKey publicKey, PrivateKey privateKey, boolean isCA, CatCert parent, byte[] fingerprint, byte[] signature, String algorithmFingerprint, String algorithmKeys, String algorithmSignatureHash)
	{
		this.version = version;
		this.subject = subject;
		this.note = note;
		this.validFrom = validFrom;
		this.validTo = validTo;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.isCA = isCA;
		this.parent = parent;
		this.fingerprint = fingerprint;
		this.signature = signature;
		this.algorithmFingerprint = algorithmFingerprint;
		this.algorithmKeys = algorithmKeys;
		this.algorithmSignatureHash = algorithmSignatureHash;
	}
	
	/**
	 * Create a new certificate and generate a keypair for it
	 * @param version Certificate Version, default is 'V1'
	 * @param subject Subject, a required field
	 * @param note Custom text field, use for whatever you want, default is empty string
	 * @param validFrom Validity period (not before), default is 1970-01-01 00:00:00 +0000
	 * @param validTo Validity period (not after), default is 1970-01-01 00:00:00 +0000
	 * @param isCA If <code>true</code>, this certificate can sign other certificates (be a parent)
	 * @param parent Parent certificate, <code>null</code> if you want it to be self-signed, default is <code>null</code>
	 * @param algorithmFingerprint Hashing algorithm used for fingerprints, default is 'SHA-1'
	 * @param algorithmKeys Cryptographic algorithm used for generating keys, encrypting, decrypting, signing and verifying
	 * @param algorithmSignatureHash Hashing algorithm used for generating and verifying signatures
	 * @throws SignatureGenerationException A wrapper for {@link InvalidKeyException}, {@link NoSuchAlgorithmException}, {@link SignatureException}, {@link IOException} that may occur during signature generation for the certificate
	 * @return
	 */
	public static CatCert create(String version, String subject, String note, Date validFrom, Date validTo, boolean isCA, CatCert parent, String algorithmFingerprint, String algorithmKeys, String algorithmSignatureHash)
	{
		CatKeyGen keys = new CatKeyGen(algorithmKeys, 2048);
		CatCert.Builder b = new CatCert.Builder()
			.setVersion(version)
			.setSubject(subject)
			.setNote(note)
			.setValidFrom(validFrom)
			.setValidTo(validTo)
			.setIsCA(isCA)
			.setPublicKey(keys.pubKey)
			.setPrivateKey(keys.privKey)
			.setFingerprintAlgorithm(algorithmFingerprint)
			.setKeyAlgorithm(algorithmKeys)
			.setSignatureHashAlgorithm(algorithmSignatureHash)
			.setParent(parent)
			.setFingerprint();
		PrivateKey privKey = (parent == null) ? b.privateKey : parent.privateKey;
		try
		{
			CatSigner sig = new CatSigner(privKey);
			b.setSignature(sig.sign(b.fingerprint, algorithmSignatureHash));
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException t)
		{
			new SignatureGenerationException("Couldn't sign a certificate.", t);
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
	 * @return New {@link CatCert} object containing all the information of <i>this one</i> but the private key
	 */
	public CatCert clonePublic()
	{
		return new CatCert(version, subject, note, validFrom, validTo, publicKey, null, isCA, parent, fingerprint, signature, algorithmFingerprint, algorithmKeys, algorithmSignatureHash);
	}
	
	/**
	 * Encrypt private key with a password
	 * @param password
	 * @return Byte array containing encrypted private key<br>
	 * <code>null</code> if this certificate does not have a private key
	 */
	public byte[] getEncryptedPrivateKey(String password)
	{
		try
		{
			if (privateKey == null)
			{
				return null;
			}
			CatCipher cipher = new CatCipher(password.getBytes(), (byte)0);
			return cipher.encrypt(privateKey.getEncoded());
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException t)
		{
			throw new CipherEncryptionException("Unable to encrypt a private key.", t);
		}
	}
	
	/**
	 * Clone this certificate and add a private key to it<br>
	 * @param encryptedPrivateKey Byte array containing a private key encrypted with a password
	 * @param password
	 * @return New {@link CatCert} object containing all the information of <i>this one</i> and the private key
	 * @throws RuntimeException NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	 */
	public CatCert getPrivateKeyCert(byte[] encryptedPrivateKey, String password)
	{
		try
		{ 
			CatCipher cipher = new CatCipher(password.getBytes(), (byte)0);
			PrivateKey privateKey = CatKeyFactory.restorePrivateKey(cipher.decrypt(encryptedPrivateKey), algorithmKeys);
			return new CatCert(version, subject, note, validFrom, validTo, publicKey, privateKey, isCA, parent, fingerprint, signature, algorithmFingerprint, algorithmKeys, algorithmSignatureHash);
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException t)
		{
			throw new CipherDecryptionException("Unable to decrypt a private key.", t);
		}
	}
	
	/**
	 * Generate a certificate's fingerprint<br>
	 * Fingerprint is a hash of a serialized certificate (fingerprint and signature values are not serialized)
	 * @return
	 */
	public byte[] fingerprint()
	{
		CatCert cert = new CatCert(version, subject, note, validFrom, validTo, publicKey, null, isCA, parent, null, null, algorithmFingerprint, algorithmKeys, algorithmSignatureHash);
		try
		{
			return MessageDigest.getInstance(cert.algorithmFingerprint).digest(toJson(cert).getBytes(Charset.forName("ISO-8859-15")));
		}
		catch (NoSuchAlgorithmException t)
		{
			throw new HashException(String.format("%s is not a valid hashing algorithm.", cert.algorithmFingerprint), t);
		}
	}
	
	/**
	 * Check if the certificate is expired
	 * @return <code>true</code> if {@link #validFrom} < NOW < {@link #validTo}
	 */
	public boolean isExpired()
	{
		Date date = CatUtils.now();
		return date.after(validFrom) && date.before(validTo);
	}
	
	/**
	 * Serialize this to JSON
	 * @see Serializer#serialize(CatCert, Type, JsonSerializationContext)
	 * @param cert
	 * @return
	 */
	public static String toJson(CatCert cert)
	{
		return gson.toJson(cert);
	}
	
	/**
	 * Deserialize this from JSON
	 * @see Serializer#deserialize(JsonElement, Type, JsonDeserializationContext)
	 * @param json
	 * @return
	 */
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
	
	@Override
	public boolean equals(Object obj)
	{
		return toString().equals(obj.toString());
	}
	
	/**
	 * Builder for {@link CatCert}
	 * @author Dany
	 *
	 */
	public static class Builder
	{
		private String version = "V1";
		private String subject = null;
		private String note = "";
		private Date validFrom = new Date(0);
		private Date validTo = new Date(0);
		private PublicKey publicKey = null;
		private PrivateKey privateKey = null;
		private boolean isCA = false;
		private CatCert parent = null;
		private byte[] fingerprint = null;
		private byte[] signature = null;
		private String algorithmFingerprint = "SHA-1";
		private String algorithmKeys = "RSA";
		private String algorithmSignatureHash = "SHA256withRSA";
		
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
		 * Set subject, who owns the certificate, a required argument
		 * @param subject
		 */
		public Builder setSubject(String subject)
		{
			this.subject = subject;
			return this;
		}
		
		/**
		 * Set note, this is a custom text field, default is empty string
		 * @param note
		 * @return
		 */
		public Builder setNote(String note)
		{
			this.note = note;
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
		 * <code>true</code> if this is a Certificate Authority and can sign other certificates<br>
		 * Default is <code>false</code>
		 * @param isCA
		 */
		public Builder setIsCA(boolean isCA)
		{
			this.isCA = isCA;
			return this;
		}
		
		/**
		 * Set certificate fingerprint, used by deserializer<br>
		 * Use {@link #setFingerprint()} to automatically calculate and assign the correct fingerprint
		 * @see #fingerprint()
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
		 * Set signature, fingerprint signed by the parent certificate, used by deserializer
		 * @see CatSigner#sign(byte[]) Code for signing
		 * @see #fingerprint Fingerprint that is being signed
		 * @see #fingerprint() Fingerprint generation
		 * @param signature
		 */
		public Builder setSignature(byte[] signature)
		{
			this.signature = signature;
			return this;
		}
		
		/**
		 * Set hashing algorithm used to generate fingerprints, default is 'SHA-1'
		 * @param algorithmFingerprint
		 * @return
		 */
		public Builder setFingerprintAlgorithm(String algorithmFingerprint)
		{
			this.algorithmFingerprint = algorithmFingerprint;
			return this;
		}
		
		/**
		 * Set algorithm used to handle keys, default is 'RSA'
		 * @param algorithmKeys
		 * @return
		 */
		public Builder setKeyAlgorithm(String algorithmKeys)
		{
			this.algorithmKeys = algorithmKeys;
			return this;
		}
		
		/**
		 * Set hashing algorithm for signatures, default is 'SHA256withRSA'
		 * @param algorithmFingerprint
		 * @return
		 */
		public Builder setSignatureHashAlgorithm(String algorithmSignatureHash)
		{
			this.algorithmSignatureHash = algorithmSignatureHash;
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
				parent = new CatCert(parent.version, parent.subject, parent.note, parent.validFrom, parent.validTo, parent.publicKey, null, parent.isCA, parent.parent, parent.fingerprint, parent.signature, parent.algorithmFingerprint, parent.algorithmKeys, parent.algorithmSignatureHash);
			}
			this.parent = parent;
			return this;
		}
		
		/**
		 * Generate a fingerprint for this builder
		 * @throws IllegalArgumentException {@link #subject} or {@link #publicKey} is <code>null</code>
		 * @see CatCert#fingerprint()
		 * @return
		 */
		public byte[] fingerprint()
		{
			if (subject == null) throw new IllegalArgumentException("Attempted to build a certificate with no subject.");
			if (publicKey == null) throw new IllegalArgumentException("Attempted to build a certificate with no public key.");
			CatCert cert = new CatCert(version, subject, note, validFrom, validTo, publicKey, privateKey, isCA, parent, fingerprint, signature, algorithmFingerprint, algorithmKeys, algorithmSignatureHash);
			return cert.fingerprint();
		}
		
		/**
		 * Build a certificate object
		 * @return
		 * @throws IllegalArgumentException Any of the following fields is <code>null</code> {@link #subject}, {@link #publicKey}, {@link #fingerprint}, {@link #signature}
		 * @throws SignatureVerificationException A wrapper for InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, IOException that may occur during certificate's signature verification
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
				if (!ver.verify(fingerprint, signature, algorithmSignatureHash)) throw new IllegalSignatureException("Attempted to build a certificate with invalid signature", signature);
			}
			catch (InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchAlgorithmException | IOException t)
			{
				throw new SignatureVerificationException("Couldn't verify certificate signature.", t);
			}
			return new CatCert(version, subject, note, validFrom, validTo, publicKey, privateKey, isCA, parent, fingerprint, signature, algorithmFingerprint, algorithmKeys, algorithmSignatureHash);
		}
	}
	
	/**
	 * Used to serialize {@link CatCert} objects to JSON format<br>
	 * Implements {@link JsonSerializer} and {@link JsonDeserializer}
	 * @author Dany
	 *
	 */
	public static class Serializer implements JsonSerializer<CatCert>, JsonDeserializer<CatCert>
	{
		private Serializer() {}
		
		/**
		 * Used internally by GSON library.<br>
		 * If you want to serialize {@link CatCert}, use {@link CatCert#toJson(CatCert)}
		 * @param cert
		 * @param type
		 * @param context
		 * @return
		 */
		@Override
		public JsonElement serialize(CatCert cert, Type type, JsonSerializationContext context)
		{
			JsonObject json = new JsonObject();
			json.addProperty("Version", cert.version);
			json.addProperty("Subject", cert.subject);
			json.addProperty("Note", cert.note);
			json.addProperty("ValidFrom", CatUtils.formatDate(cert.validFrom));
			json.addProperty("ValidTo", CatUtils.formatDate(cert.validTo));
			json.addProperty("IsCA", cert.isCA);
			json.addProperty("FingerprintAlgorithm", cert.algorithmFingerprint);
			json.addProperty("KeyAlgorithm", cert.algorithmKeys);
			json.addProperty("SignatureHashAlgorithm", cert.algorithmSignatureHash);
			if (cert.fingerprint != null)
			{
				json.addProperty("Fingerprint", DatatypeConverter.printHexBinary(cert.fingerprint));
			}
			if (cert.signature != null)
			{
				json.addProperty("Signature", DatatypeConverter.printHexBinary(cert.signature));
			}
			json.addProperty("PublicKey", DatatypeConverter.printHexBinary(cert.publicKey.getEncoded()));
			if (cert.parent != null)
			{
				json.add("Parent", gson.toJsonTree(cert.parent));
			}
			return json;
		}
		
		/**
		 * Used internally by GSON library.<br>
		 * If you want to deserialize {@link #CatCert()}, use {@link CatCert#fromJson(String)}, {@link CatCert#fromJson(File)}
		 * @param jsonElement
		 * @param type
		 * @param context
		 * @return
		 * @throws JsonParseException
		 */
		@Override
		public CatCert deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context) throws JsonParseException
		{
			try
			{
				JsonObject json = jsonElement.getAsJsonObject();
				CatCert.Builder b = new CatCert.Builder()
					.setVersion(json.get("Version").getAsString())
					.setSubject(json.get("Subject").getAsString())
					.setIsCA(json.get("IsCA").getAsBoolean())
					.setNote(json.get("Note").getAsString())
					.setFingerprint(DatatypeConverter.parseHexBinary(json.get("Fingerprint").getAsString()))
					.setSignature(DatatypeConverter.parseHexBinary(json.get("Signature").getAsString()))
					.setFingerprintAlgorithm(json.get("FingerprintAlgorithm").getAsString())
					.setKeyAlgorithm(json.get("KeyAlgorithm").getAsString())
					.setSignatureHashAlgorithm(json.get("SignatureHashAlgorithm").getAsString());
				b.setPublicKey(CatKeyFactory.restorePublicKey(DatatypeConverter.parseHexBinary(json.get("PublicKey").getAsString()), b.algorithmKeys))
					.setValidFrom(CatUtils.parseDate(json.get("ValidFrom").getAsString()))
					.setValidTo(CatUtils.parseDate(json.get("ValidTo").getAsString()));
				if (json.has("Parent"))
				{
					b.setParent(fromJson(json.get("Parent").toString()));
				}
				return b.build();
			}
			catch (RuntimeParseException t)
			{
				throw new JsonParseException("Couldn't parse Date.", t.getCause());
			}
		}
	}
}