package catdany.cryptocat.api;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import catdany.cryptocat.api.CatUtils.RuntimeParseException;
import catdany.cryptocat.api.exception.SignatureGenerationException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class CatTimestamp
{
	static final Gson gson = new GsonBuilder().registerTypeAdapter(CatTimestamp.class, new Serializer()).create();
	
	public final Date time;
	public final CatSignature sig;
	public final byte[] fingerprint;
	public final byte[] signedBytes;
	
	public CatTimestamp(Date time, CatSignature sig, byte[] fingerprint, byte[] signedBytes)
	{
		this.time = time;
		this.sig = sig;
		this.fingerprint = fingerprint;
		this.signedBytes = signedBytes;
	}
	
	/**
	 * Generate a timestamp from now and sign it with a certificate stored in {@link CatSignature}
	 * @throws RuntimeException A wrapper for NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException
	 * @param sig
	 * @return
	 */
	public static CatTimestamp generate(CatSignature sig)
	{
		try
		{
			Date time = CatUtils.now();
			byte[] fingerprint = getFingerprint(sig, time);
			byte[] signedBytes = new CatSigner(sig.cert.privateKey).sign(fingerprint, sig.cert.algorithmSignatureHash);
			return new CatTimestamp(time, sig, fingerprint, signedBytes);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException t)
		{
			throw new SignatureGenerationException("Couldn't generate a timestamp.", t);
		}
	}
	
	public static CatTimestamp fromJson(String json)
	{
		return gson.fromJson(json, CatTimestamp.class);
	}
	
	public String toJson()
	{
		return gson.toJson(this);
	}
	
	public static byte[] getFingerprint(CatSignature sig, Date time)
	{
		CatSignature sig0 = new CatSignature(sig.signedBytes, sig.cert, sig.filename, null);
		try
		{
			return MessageDigest.getInstance(sig.cert.algorithmFingerprint).digest((sig0.toJson() + CatUtils.formatDate(time)).getBytes(Charset.forName("ISO-8859-15")));
		}
		catch (NoSuchAlgorithmException t)
		{
			throw new RuntimeException(String.format("%s is not a valid hashing algorithm.", sig.cert.algorithmFingerprint), t);
		}
	}
	
	public static class Serializer implements JsonSerializer<CatTimestamp>, JsonDeserializer<CatTimestamp>
	{
		@Override
		public JsonElement serialize(CatTimestamp src, Type typeOfSrc, JsonSerializationContext context)
		{
			JsonObject json = new JsonObject();
			json.addProperty("Date", CatUtils.formatDate(src.time));
			json.addProperty("Fingerprint", DatatypeConverter.printHexBinary(src.fingerprint));
			json.addProperty("Signature", DatatypeConverter.printHexBinary(src.signedBytes));
			return json;
		}
		
		@Override
		public CatTimestamp deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException
		{
			JsonObject j = json.getAsJsonObject();
			try
			{
				return new CatTimestamp(
							CatUtils.parseDate(j.get("Date").getAsString()),
							null,
							DatatypeConverter.parseHexBinary(j.get("Fingerprint").getAsString()),
							DatatypeConverter.parseHexBinary(j.get("Signature").getAsString())
						);
			}
			catch (RuntimeParseException t)
			{
				throw new JsonParseException("Couldn't parse date of the timestamp.", t.getCause());
			}
		}
	}
}