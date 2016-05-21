package catdany.cryptocat.api;

import java.lang.reflect.Array;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

public class CatUtils
{
	private static DateFormat dateFormat = null;
	
	public static Date parseDate(String format) throws ParseException
	{
		return dateFormat.parse(format);
	}
	
	public static String formatDate(Date date)
	{
		return dateFormat.format(date);
	}
	
	/**
	 * Set date format used in CryptoCat API
	 * @param dateFormat
	 */
	public static void setDateFormat(DateFormat dateFormat)
	{
		CatUtils.dateFormat = dateFormat;
	}
	
	/**
	 * Get date format used in CryptoCat API
	 * @return
	 */
	public static DateFormat getDateFormat()
	{
		return dateFormat;
	}
	
	public static Date now()
	{
		return Calendar.getInstance().getTime();
	}
	
	/**
	 * Concatenate arrays
	 * @return
	 */
	public static <T>T[] concatArrays(T[] a, T[] b)
	{
		@SuppressWarnings("unchecked")
		T[] result = (T[])Array.newInstance(a.getClass(), a.length + b.length);
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, 0, b.length);
		return result;
	}
	
	/**
	 * Concatenate byte arrays
	 * @param a
	 * @param b
	 * @return
	 */
	public static byte[] concatArrays(byte[] a, byte[] b)
	{
		byte[] result = new byte[a.length + b.length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, 0, b.length);
		return result;
	}
}