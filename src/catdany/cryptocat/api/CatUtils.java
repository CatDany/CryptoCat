package catdany.cryptocat.api;

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
}