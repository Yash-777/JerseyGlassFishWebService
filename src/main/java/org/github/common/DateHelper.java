package org.github.common;

import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.zone.ZoneOffsetTransition;
import java.time.zone.ZoneOffsetTransitionRule;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;

/*
Central European Time (CET), used in most parts of Europe and a few North African countries,
is a standard time which is 1 hour ahead of Coordinated Universal Time (UTC).
The time offset from UTC can be written as UTC+01:00.

European countries using CET in the winter and CEST in the summer:

https://www.worldtimebuddy.com/

Time zone : https://time.is/CET
Currently Central European Summer Time (CEST), UTC +2
Standard time (Central European Time (CET), UTC +1) starts October 25, 2020

CET alternates between UTC+1 (standard time) and UTC+2 (when daylight saving time (DST) is observed).
All countries in the CET time zone observe DST (UTC+2) from 02:00 am on the last Sunday of March until
 03:00 am on the last Sunday of October.
 */
public class DateHelper {
	static String formatStr = "yyyy-MM-dd'T'HH:mm:ss";
	public static Date lenientStrictParseDate(String aSource, String zone) throws ParseException {
		DateFormat dateFormat = new SimpleDateFormat(formatStr);
		dateFormat.setTimeZone(TimeZone.getTimeZone(zone));
		//dateFormat.setLenient(false);
		Date date = dateFormat.parse(aSource);
		System.out.format(zone + " Old [%s]= New Date [%s]\n", aSource, date.toGMTString());
		getTimeStamp(date);
		return date;
	}
	public static Date parseDate(String aSource) throws ParseException {
		DateFormat dateFormat = new SimpleDateFormat(formatStr, Locale.ENGLISH);
		Date date = dateFormat.parse(aSource);
		System.out.format("attribute [%s]= Date [%s]\n", aSource, date.toString());
		getTimeStamp(date);
		return date;
	}
	
	public static void main(String[] args) throws ParseException {
		//TimeZone.setDefault( TimeZone.getTimeZone("UTC") ); // Default: java.sql.Timestam. Change: GMT, CET, UTC
		//System.setProperty("user.timezone", "UTC"); // or -Duser.timezone=GMT in the JVM args.
		
		String timeZone = System.getProperty("user.timezone");
		System.out.println("Time Zone:"+timeZone); // Europe/Berlin
		System.out.println("Zone System:"+ timeZone +", TimeZone.getDefault().toZoneId(): "+ZoneId.systemDefault());
		
		// Initializing the first formatter
		DateFormat DFormat = DateFormat.getDateTimeInstance();
		System.out.println("Object: " + DFormat);
		String str = DFormat.format(new Date());
		System.out.println("Displaying the string time:"+ str); // Jul 19, 2021, 11:57:12 AM
		System.out.println("Leniency: "+ DFormat.isLenient());
		DFormat.setLenient(false); // Changing the leniency
		System.out.println("Displaying the modified leniency: " + DFormat.isLenient());

		DateFormat dateFormat222 = new SimpleDateFormat(formatStr, Locale.ENGLISH);
		//dateFormat222.setLenient(true); // java.text.ParseException: Unparseable date: "2020-03-29T02:00:00"
		//dateFormat222.setTimeZone(TimeZone.getTimeZone("UTC"));
		//setLenient(false) and TimeZone("UTC") {{RESULTS}}: 2020-03-29T02:00:00 -to- Sun Mar 29 04:00:00 CEST 2020
		//setLenient(true)  and TimeZone("CET") {{RESULTS}}: 2020-03-29T02:00:00 -to- Sun Mar 29 03:00:00 CEST 2020
		Date dates222 = dateFormat222.parse("2020-03-29T02:00:00");
		System.out.println("Short Hour CET 2nd :"+dates222); // Sun Mar 29 03:00:00 CEST 2020
		
		// Displaying the modified leniency
		System.out.println("New Leniency: " + dateFormat222.isLenient());
		
		/* String[] datesArr = {
				"2020-03-29T12:00:00", "2020-03-29T01:00:00", "2020-03-29T02:00:00", "2020-03-29T03:00:00", "2020-03-29T04:00:00", // Short Day on 2nd hour
				"2020-10-25T12:00:00", "2020-10-25T01:00:00", "2020-10-25T02:00:00", "2020-10-25T03:00:00"  // Long  Day on 2nd hour
				};
		checkCETDates(datesArr); */
		
		
		/*String startDate = "2020-03-29T01:00:00";
		String endDate = "2020-03-29T02:00:00";
		compareTwoTimeStamps(startDate, endDate);
		
		String startDate2 = "2020-03-29T03:00:00";
		String endDate2 = "2020-03-29T04:00:00";
		compareTwoTimeStamps(startDate2, endDate2);
		
		System.out.println("------------------------------");
		
		try {
			lenientStrictParseDate(dateStr, "UTC");
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		try {
			parseDate(dateStr);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		Instant instant = Instant.parse( dateStr + "Z"); // `Instant` is always in UTC.
		java.util.Date date = java.util.Date.from( instant );
		System.out.println("UTC : "+date);
		
		String prop = System.getProperty("java.time.zone.DefaultZoneRulesProvider");
		System.out.println("DefaultZoneRulesProvider : "+ prop);
		
		displayZonedDate(dateStr, "UTC"); // UTC, GMT, UT
		displayZonedDate(dateStr, "CET");
		//displayZonedDate(dateStr, "CETDST");
		
		// displayZoneRules();
		 */
	}
	
	public static Timestamp getTimestamp(String strDate) {
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
		LocalDateTime dateTime = LocalDateTime.parse(strDate, formatter);
								//LocalDateTime.of(10000, Month.DECEMBER, 30, 12, 10, 05);
		
		Timestamp valueOf = java.sql.Timestamp.valueOf(dateTime);
		System.out.format("TimeStamp Local : [%-30s]\n", valueOf.toString());
		
		java.sql.Date sqlDate = new java.sql.Date( valueOf.getTime() );
		System.out.format("java.sql.Date : [%-30s]\n", sqlDate);
		
		return valueOf;
		
		/*LocalDateTime with = dateTime.with(TemporalAdjusters.lastInMonth(DayOfWeek.SUNDAY));
		int dayOfMonth = with.getDayOfMonth();
		System.out.println("Last Sunday of Month: "+dayOfMonth);*/
	}
	public static void checkCETDates(String[] datesArr) throws ParseException {
		String formatStr = "yyyy-MM-dd'T'HH:mm:ss";
		for (String strDate : datesArr) {
			
			DateFormat dateFormat = new SimpleDateFormat(formatStr);
			dateFormat.setTimeZone(TimeZone.getTimeZone("UTC")); // Provided date as CET, Converting corresponding Default UTC date
			Date dates = dateFormat.parse(strDate);
			
			String utcDate = dateFormat.format(dates);
			
			/*SimpleTimeZone[id=Europe/Berlin,dstSavings=3600000,useDaylight=true]
					1603591200000 : UTC TimeStamp: 2020-10-25 02:00:00.0
					1603587600    : CET
					      3600    : dstSavings*/
			Calendar cal = new GregorianCalendar();
			cal.setTimeZone(TimeZone.getTimeZone("UTC"));
			cal.setTimeInMillis(dates.getTime());
			
			
			DateFormat dateFormat22 = new SimpleDateFormat(formatStr);
			dateFormat22.setLenient(true);
			//dateFormat22.setTimeZone(TimeZone.getTimeZone("CET")); // UTC, -01:00, GMT, GMT-7, IST-"Asia/Kolkata"
			Date dates22 = dateFormat22.parse(utcDate);
			System.out.println("New Leniency: " + dateFormat22.isLenient());
			
			// Don’t use GMT-7 as a time zone. Use for example America/Los_Angeles. Of course select the time zone that makes sense for your situation.
			// https://www.epochconverter.com/  - Sun, 29 Mar 2020 02:00:00 GMT,  1585447200000 = 1585447200000
			//System.out.println("Timestamp in milliseconds:"+ dates.getTime() + ", Epoch Time:"+dates22.getTime()/ 1000);
			
			/*System.out.println("UTC - :"+utcDate+" CET2UTC:"+dates22+" TimeStamp UTC: "+ new java.sql.Timestamp(dates22.getTime())+
					"TimeStamp CET: "+ new java.sql.Timestamp(dates22.getTime()));*/
			
			DateFormat dateFormat2 = new SimpleDateFormat(formatStr, Locale.ENGLISH);
			dateFormat2.setTimeZone(TimeZone.getTimeZone("CET"));
			Date dates2 = dateFormat2.parse(strDate);
			//System.out.format("UTC - [%s] = [%s] GMT:%s\n", strDate, dates2, dates2.toGMTString());
			
			
			displayKeyVal("Privided", strDate);
			displayKeyVal("Locale.CET", dates22+"");
			/*
			displayKeyVal("convertUTCtoCET", convertUTCtoCET(strDate) );
			
			displayKeyVal("Locale.UTC", dates+"");
			displayKeyVal("UTC Str", utcDate);
			displayKeyVal("GMT String", dates.toGMTString());
			displayKeyVal("Locale.CET", dates22+"");
			//displayKeyVal("Locale.ENGLISH", dates2+"");
			
			//displayKeyVal("UTC Time Default(CET)", new java.sql.Timestamp(dates.getTime())+"");
			//displayKeyVal("UTC - CET Time", new java.sql.Timestamp(dates22.getTime())+"");
			//displayKeyVal("ENGLISH Time", new java.sql.Timestamp(dates2.getTime())+"");
			
			//displayKeyVal("GregorianCalendar", cal.getTime()+"");
			//displayKeyVal("TimeStamp GC", new java.sql.Timestamp(cal.getTimeInMillis())+"");
			
			//displayKeyVal("TimeStamp Local", (getTimestamp(strDate)).toString());
			 */
			System.out.println("======================");
		}
	}
	
	public static void displayKeyVal(String key, String val) {
		System.out.format("[%-25s] : [%-35s]\n", key, val);
	}
	
	public static long compareTwoTimeStamps(String startDate, String endDate) throws ParseException {
		Date start = parseDate(startDate);
		Date end = parseDate(endDate);
		
		java.sql.Timestamp startTime = getTimeStamp(start);
		java.sql.Timestamp endTime = getTimeStamp(end);
		
		long startTimeMilli = startTime.getTime();
		long endTimeMilli = endTime.getTime();
		long diff = endTimeMilli - startTimeMilli;
		
		//long diffSeconds = diff / 1000;
		//long diffMinutes = diff / (60 * 1000);
		long diffHours = diff / (60 * 60 * 1000);
		//long diffDays = diff / (24 * 60 * 60 * 1000);
		
		System.out.format("Start:%s, End:%s\n", start, end);
		System.out.println("Difference in Hours : "+ diffHours);
		if (diffHours >= 1) {
			Timestamp oneHourAgo = new Timestamp(endTime.getTime() - (60 * 60 * 1000));
			System.out.println("--- Before: "+ endTime.toLocaleString());
			System.out.println("--- After: "+ oneHourAgo.toLocaleString());
		}
		return diffHours;
	}
	
	
	public static void displayZonedDate(String dateStr, String zone) {
		Instant instant = Instant.parse( dateStr + "Z");
		ZoneId zoneId = ZoneId.of( zone ); // Define a time zone rather than rely implicitly on JVM’s current default time zone.
		ZonedDateTime zdt = ZonedDateTime.ofInstant( instant , zoneId );  // Assign a time zone adjustment from UTC.
		java.util.Date dateZoned = java.util.Date.from( zdt.toInstant() );
		System.out.println(zone+" : "+dateZoned);
	}
	
	public static Timestamp getTimeStamp(Date date) { //Date dbResponseTime = new java.util.Date();
		Timestamp timestamp = new java.sql.Timestamp(date.getTime());
		System.out.println("Timestamp :"+ timestamp);
		return timestamp;
	}
	
	private static String convertUTCtoCET(String UTCDate) throws ParseException {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		Date date = formatter.parse(UTCDate);
		
		SimpleDateFormat FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String dateValue = FORMATTER.format(date);
		
		SimpleDateFormat DF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		DF.setLenient(true);
		DF.setTimeZone(TimeZone.getTimeZone("UTC"));
		SimpleDateFormat DF1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date startDate = DF.parse(dateValue);
		
		DF1.setTimeZone(TimeZone.getTimeZone("CET"));
		String CETDateFormat = DF1.format(startDate);
		return CETDateFormat;
	}
	
	public static void displayZoneRules() {
		ZoneId zone = ZoneId.of("CET");
		System.out.println(zone);
		System.out.println(zone.getRules());
		for (ZoneOffsetTransition trans : zone.getRules().getTransitions()) {
		  System.out.println(trans);
		}
		for (ZoneOffsetTransitionRule rule : zone.getRules().getTransitionRules()) {
		  System.out.println(rule);
		}
	}
}
