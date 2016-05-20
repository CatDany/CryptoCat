package catdany.cryptocat;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;

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
				JsonObject json = parser.parse(read).getAsJsonObject();
				String action = json.get("Action").getAsString();
				if (action.equals("sign"))
				{
					CatCert cert = CatCert.fromJson(new File(json.get("Certificate").getAsString()));
					if (cert.privateKey == null)
					{
						throw new NullPointerException("Certificate does not have a private key attached.");
					}
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
					printCert(ver.sig.cert, r);
					
				}
				else if (action.equals("makecert"))
				{
					CatCert cert = CatCert.create("V1", json.get("Subject").getAsString(), dateFormat.parse(json.get("ValidFrom").getAsString()), dateFormat.parse(json.get("ValidTo").getAsString()), json.get("IsCA").getAsBoolean(), json.has("Parent") ? CatCert.fromJson(new File(json.get("Parent").getAsString())) : null);
					Files.write(CatCert.toJson(cert).toString(), new File(json.get("Output").getAsString()), Charset.defaultCharset());
					sysout("Created a certificate.");
				}
				else if (action.equals("printcert"))
				{
					CatCert cert = CatCert.fromJson(new File(json.get("File").getAsString()));
					printCert(cert, r);
				}
			}
			catch (Throwable t)
			{
				t.printStackTrace();
			}
		}
	}
	
	public static void sysout(String format, Object... args)
	{
		System.out.println(String.format(format, args));
	}
	
	public static void printCert(CatCert cert, BufferedReader r) throws IOException
	{
		sysout("- CERTIFICATE");
		sysout("--- Subject:     %s", cert.subject);
		sysout("--- Version:     %s", cert.version);
		sysout("--- Type:        %s", cert.isCA ? "CA" : "Generic");
		sysout("--- Validity Period");
		sysout("----- From:      %s", dateFormat.format(cert.validFrom));
		sysout("----- To:        %s", dateFormat.format(cert.validTo));
		sysout("--- Fingerprint: %s", DatatypeConverter.printHexBinary(cert.fingerprint));
		if (cert.parent == null)
		{
			sysout("--- Self Signed.");
		}
		else
		{
			sysout("--- Signed by: %s", cert.parent.subject);
		}
		sysout("- CERTIFICATE END");
		if (cert.parent != null)
		{
			System.out.print("Print parental certificate (1=Yes)? ");
			if (r.readLine().equals("1"))
			{
				printCert(cert.parent, r);
			}
		}
	}
}