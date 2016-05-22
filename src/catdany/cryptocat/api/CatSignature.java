package catdany.cryptocat.api;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import catdany.cryptocat.api.exception.FingerprintViolationException;
import catdany.cryptocat.api.exception.IllegalSignatureException;
import catdany.cryptocat.api.exception.RuntimeIOException;
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

public class CatSignature
{
	static final Gson gson = new GsonBuilder().registerTypeAdapter(CatSignature.class, new Serializer()).create();
	
	public final byte[] signedBytes;
	public final CatCert cert;
	public final String filename;
	public final CatTimestamp timestamp;
	
	public CatSignature(byte[] signedBytes, CatCert cert, String filename, CatTimestamp timestamp)
	{
		this.signedBytes = signedBytes;
		this.cert = cert;
		this.filename = filename;
		if (timestamp != null)
		{
			this.timestamp = new CatTimestamp(timestamp.time, this, timestamp.fingerprint, timestamp.signedBytes);
			byte[] actualFingerprint = CatTimestamp.getFingerprint(this, timestamp.time);
			if (!Arrays.equals(actualFingerprint, timestamp.fingerprint)) throw new FingerprintViolationException("Signature has invalid timestamp fingerprint.", timestamp.fingerprint, actualFingerprint);
			CatVerifier ver = new CatVerifier(cert.publicKey);
			try
			{
				if (!ver.verify(timestamp.fingerprint, timestamp.signedBytes, cert.algorithmSignatureHash)) throw new IllegalSignatureException("Signature has invalid timestamp signature.", timestamp.signedBytes);
			}
			catch (InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchAlgorithmException | IOException t)
			{
				throw new SignatureVerificationException("Couldn't verify signature on a timestamp.", t);
			}
		}
		else
		{
			this.timestamp = null;
		}
	}
	
	/**
	 * @throws RuntimeException - A wrapper for {@link IOException}
	 * @param file
	 * @return
	 */
	public static CatSignature fromJson(File file)
	{
		try
		{
			return gson.fromJson(new FileReader(file), CatSignature.class);
		}
		catch (IOException t)
		{
			throw new RuntimeIOException(t);
		}
	}
	
	public static CatSignature fromJson(String json)
	{
		return gson.fromJson(json, CatSignature.class);
	}
	
	public String toJson()
	{
		return gson.toJson(this);
	}
	
	public static class Serializer implements JsonSerializer<CatSignature>, JsonDeserializer<CatSignature>
	{
		@Override
		public JsonElement serialize(CatSignature src, Type typeOfSrc, JsonSerializationContext context)
		{
			JsonObject json = new JsonObject();
			json.addProperty("Filename", src.filename);
			json.addProperty("Signature", DatatypeConverter.printHexBinary(src.signedBytes));
			json.add("Certificate", CatCert.gson.toJsonTree(src.cert.clonePublic()));
			json.add("Timestamp", CatTimestamp.gson.toJsonTree(src.timestamp));
			return json;
		}
		
		@Override
		public CatSignature deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException
		{
			JsonObject j = json.getAsJsonObject();
			return new CatSignature(
						DatatypeConverter.parseHexBinary(j.get("Signature").getAsString()),
						CatCert.fromJson(j.get("Certificate").toString()),
						j.get("Filename").getAsString(),
						CatTimestamp.fromJson(j.get("Timestamp").toString())
					);
		}
	}
}