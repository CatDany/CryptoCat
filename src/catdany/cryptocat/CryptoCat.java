package catdany.cryptocat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import catdany.cryptocat.api.CatCert;
import catdany.cryptocat.api.CatUnzipper;
import catdany.cryptocat.api.CatUtils;
import catdany.cryptocat.api.CatZipper;

import com.google.common.io.Files;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class CryptoCat
{
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
	
	public static void main(String[] args) throws Exception
	{
		CatUtils.setDateFormat(dateFormat);
		if (args.length > 0)
		{
			if (args[0].equals("demo"))
			{
				runDemo();
			}
			else if (args[0].equals("request"))
			{
				String request = "";
				for (int i = 1; i < args.length; i++)
				{
					request += args[i] + " ";
				}
				request = request.substring(0, request.length() - 1);
				parseRequest(new JsonParser(), request);
			}
		}
		else
		{
			sysout("Runtime arguments are not specified. Try 'demo'");
		}
	}
	
	public static void runDemo() throws Exception
	{
		sysout("Welcome to CryptoCat Demo.");
		sysout("All dates are using '%s' format.", dateFormat.toPattern());
		BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
		JsonParser parser = new JsonParser();
		while (true)
		{
			try
			{
				System.out.print("JSON request: ");
				String read = r.readLine();
				parseRequest(parser, read);
			}
			catch (Throwable t)
			{
				t.printStackTrace();
			}
		}
	}
	
	public static void parseRequest(JsonParser parser, String request) throws Exception
	{
		JsonObject json = parser.parse(request).getAsJsonObject();
		String action = json.get("Action").getAsString();
		if (action.equals("sign"))
		{
			File encryptedPrivateKeyFile = new File(json.get("PrivateKey").getAsString());
			byte[] encryptedPrivateKey = new byte[2048];
			FileInputStream fis = new FileInputStream(encryptedPrivateKeyFile);
			int len = fis.read(encryptedPrivateKey);
			fis.close();
			encryptedPrivateKey = Arrays.copyOfRange(encryptedPrivateKey, 0, len);
			CatCert cert = CatCert.fromJson(new File(json.get("Certificate").getAsString())).getPrivateKeyCert(encryptedPrivateKey, json.get("Password").getAsString());
			CatZipper sig = new CatZipper(new File(json.get("File").getAsString()), new File(json.get("Output").getAsString()), cert);
			sig.zip();
			sysout("Signed.");
		}
		else if (action.equals("verify"))
		{
			CatUnzipper ver = new CatUnzipper(new File(json.get("File").getAsString()));
			if (ver.verify())
			{
				sysout("Signature is valid. Timestamp: %s", CatUtils.formatDate(ver.sig.timestamp.time));
			}
			else
			{
				sysout("INVALID SIGNATURE.");
			}
			sysout("- CERTIFICATE ------------------------------------------------------");
			printCert(ver.sig.cert, true, 0);
			sysout("- CERTIFICATE END --------------------------------------------------");
			
		}
		else if (action.equals("makecert"))
		{
			CatCert parent = null;
			if (json.has("Parent"))
			{
				File encryptedPrivateKeyFile = new File(json.get("ParentPrivateKey").getAsString());
				byte[] encryptedPrivateKey = new byte[2048];
				FileInputStream fis = new FileInputStream(encryptedPrivateKeyFile);
				int len = fis.read(encryptedPrivateKey);
				fis.close();
				encryptedPrivateKey = Arrays.copyOfRange(encryptedPrivateKey, 0, len);
				parent = CatCert.fromJson(new File(json.get("Parent").getAsString())).getPrivateKeyCert(encryptedPrivateKey, json.get("ParentPassword").getAsString());
			}
			CatCert cert = CatCert.create("V1", json.get("Subject").getAsString(), json.has("Note") ? json.get("Note").getAsString() : "", dateFormat.parse(json.get("ValidFrom").getAsString()), dateFormat.parse(json.get("ValidTo").getAsString()), json.get("IsCA").getAsBoolean(), parent, "SHA-1", "RSA", "SHA256withRSA");
			Files.write(CatCert.toJson(cert).toString(), new File(json.get("Output").getAsString()), Charset.defaultCharset());
			byte[] encryptedPrivateKey = cert.getEncryptedPrivateKey(json.get("Password").getAsString());
			File encryptedPrivateKeyFile = new File(json.get("PrivateKeyOutput").getAsString());
			FileOutputStream fos = new FileOutputStream(encryptedPrivateKeyFile);
			fos.write(encryptedPrivateKey);
			fos.close();
			sysout("Created a certificate.");
		}
		else if (action.equals("printcert"))
		{
			CatCert cert = CatCert.fromJson(new File(json.get("File").getAsString()));
			sysout("- CERTIFICATE ------------------------------------------------------");
			printCert(cert, true, 0);
			sysout("- CERTIFICATE END --------------------------------------------------");
		}
	}
	
	public static void sysout(String format, Object... args)
	{
		System.out.println(String.format(format, args));
	}
	
	public static void printCert(CatCert cert, boolean printParents, int parentIteration) throws IOException
	{
		String prefix = "";
		for (int i = 0; i < parentIteration; i++)
		{
			prefix += "--";
		}
		sysout(prefix + "--- Subject:               %s", cert.subject);
		sysout(prefix + "--- Note:                  %s", cert.note);
		sysout(prefix + "--- Version:               %s", cert.version);
		sysout(prefix + "--- Type:                  %s", cert.isCA ? "CA" : "Generic");
		sysout(prefix + "--- Validity Period");
		sysout(prefix + "----- From:                %s", dateFormat.format(cert.validFrom));
		sysout(prefix + "----- To:                  %s", dateFormat.format(cert.validTo));
		sysout(prefix + "--- Algorithms");
		sysout(prefix + "----- Fingerprint Hashing: %s", cert.algorithmFingerprint);
		sysout(prefix + "----- Keys:                %s", cert.algorithmKeys);
		sysout(prefix + "----- Signature Hashing:   %s", cert.algorithmSignatureHash);
		sysout(prefix + "--- Fingerprint:           %s", DatatypeConverter.printHexBinary(cert.fingerprint));
		if (cert.parent == null)
		{
			sysout(prefix + "--- Self Signed.");
		}
		else
		{
			if (printParents)
			{
				sysout(prefix + "--- Parent --------------------------------------------------------");
				printCert(cert.parent, true, parentIteration + 1);
			}
			else
			{
				sysout(prefix + "--- Signed by: %s", cert.parent.subject);
			}
		}
	}
}