package org.github.common;

import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class DateHelper2 {
	public static void main(String[] args) throws ParseException {
		// Short Day: 28/3 93, Normal: 97
		Date message_firstDate = stringToDate("28-MAR-2021 00:00:00");
		String schIntFirst = formatDate(message_firstDate, "yyyyMMddHHmm");
		
		int timeSeries_periodquantities_length = 93, minutes = 15;
		// Short Day Dates and Long Day dates
		Date schIntervall = addMinutes(message_firstDate, (timeSeries_periodquantities_length - 1) * minutes * 2);
		schIntervall = addDays(schIntervall, -1);
		
		String schIntLast = formatDate(schIntervall, "yyyyMMddHHmm");
		
		System.out.println("---------------------- schIntFirst: "+schIntFirst);
		System.out.println("----------------------  schIntLast: "+schIntLast);
		
		displayCETtoUTC("2020-03-29", "2020-03-29");
		displayCETtoUTC("2019-03-29", "2019-03-29");
		
		displayCETtoUTC("2019-03-26T23:00Z", "2019-03-27T23:00Z");
		// UTC= First:2019-03-25T23:00Z, Last:2019-03-27T23:00Z
		
		String dateStrCET = "2019-03-25T23:00Z";
		
		// TZD  = time zone designator (Z or +hh:mm or -hh:mm)
		if (dateStrCET.contains("Z")) {
			String firstDate = convertUTCToCET(dateStrCET);
			System.out.println("convertUTCToCET :"+firstDate);
		}
		
		Date currentDate = new java.util.Date();
		getTimeStamp(currentDate);
		
		String dateStr = "31-DEC-99999 07:36:26";
		javaUtilSQlDates(dateStr);
		
		//LocalDate todayLocalDate = LocalDate.of(99991, Month.DECEMBER, 30);
		LocalDateTime dateTime = LocalDateTime.of(10000, Month.DECEMBER, 30, 12, 10, 05);
		System.out.println("LocalDate:"+dateTime.toString());
		java.sql.Date sqlDate = java.sql.Date.valueOf( dateTime.toLocalDate() );
		System.out.println("SQL Date: "+sqlDate);
		
		
		// 15817485860001L - 2471-03-27 19:04:20.001
		// 1581748586000131L - 52093-08-13 09:13:20.131
		Timestamp timestamp = new java.sql.Timestamp(1581748586000131L);
		System.out.println("Timestamp LONG :"+ timestamp);
		
		SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss.SSSS");
		Date date2 = stringToDate(sdf, "15-Feb-2020 07:36:26.45097");
		getTimeStamp(date2);
		
		// SimpleDateFormat.parse() - NumberFormatException: For input string: "22200222E.222002224EE44"
		// Deal triggered time in text format. DateFormat:'dd-MMM-yyyy HH:mm:ss' and TimeZone:'CET'
		numberFormatEx( currentDate );
		numberFormatEx( stringToDate("09-Jan-2014 10:36:26") );
		
		String dateTimeinCET = dateTimeinCET( currentDate );
		System.out.println("CET: "+ dateTimeinCET);
		
		/*getSysDate_PlusMin(2 * 60 * 1000, "dd.MM.yyyy HH:mm:ss"); // M Month, m Mins, s sec, S mill
		getSysDate_LastQuarterMins("dd.MM.yyyy HH:mm:ss");
		
		getRoundValue(10);
		getRoundValue(59);*/
		
		/*String timeStr = "15:50"; // HH:MM (OR) MM:SS
		String timeStr2 = "16:50"; // HH:MM (OR) MM:SS
		boolean timeGreater = isTimeGreater(timeStr, timeStr2);
		System.out.println("isTimeGreater: "+ timeGreater);
		
		String startDateStr = "24/08/2019", endDateStr = "25/09/2019";
		Date startDate = DateHelper.parseDate(startDateStr, formatStr);
		Date endDate = DateHelper.parseDate(endDateStr, formatStr);
		
		int numberofDaysInBetw = getDaysBetween(startDate, endDate);
		System.out.println("Number of Days In Between two Dates : "+ numberofDaysInBetw);
		
		int numberofDaysInBetwJoda = getDaysBetween(startDateStr, endDateStr);
		System.out.println("Number of Days In Between two Dates JODA: "+ numberofDaysInBetwJoda);
		
		changeDateFormat( startDateStr, formatStr, "dd.MM.yyyy");
		
		Date currentDate = new Date();
		String format = reverseDateFormat.format(currentDate);
		System.out.println("Reverse Format [SimpleDateFormat]: "+format);
		
		String formatedDate = DateHelper.formatDate(currentDate, "yyyyMMdd_HHmmss");
		System.out.println("Current Date for Report File : "+formatedDate);
		
		System.out.println("Date SYSDATE Minus Days: "+ setDate("sysdate-360") );
		System.out.println("Date SYSDATE Add Days: "+ setDate("sysdate+1") );*/
		
		/*int days = 20;
		GregorianCalendar dayCountofYear = new GregorianCalendar(2020,Calendar.JANUARY, 1);
		dayCountofYear.add(Calendar.DAY_OF_YEAR, days);
		System.out.println("GregorianCalendar: "+ dateFormat.format(dayCountofYear.getTime()));
		
		String initialDay = "01/01/2020";
		Date nextDate = addDaysToDate(initialDay, 20);
		System.out.println("After Adding Number of Days:"+nextDate);
		
		Date firstDate = DateHelper.parseDate(initialDay, formatStr);*/
		
		/*int daysBetween = getDaysBetween(firstDate, nextDate);
		System.out.println(days + " - Days Between - "+daysBetween);*/
	}
	
	
	public static void getRoundValue(int minutes) {
		int min = (int) (Math.round(minutes / 15.0) * 15.0);
		System.out.println("getRoundValue : "+min);
	}
	
	private static String lastDateCETToUTCFormat(String lastDateCET) throws ParseException {
		SimpleDateFormat DF = new SimpleDateFormat("yyyy-MM-dd");
		DF.setLenient(true);
		DF.setTimeZone(TimeZone.getTimeZone("CET"));
		
		SimpleDateFormat DF1 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
		
		Date startDate = DF.parse(lastDateCET);
		
		Calendar calender = Calendar.getInstance(); 
		calender.setTime(startDate); 
		calender.add(Calendar.DATE, 1);
		startDate = calender.getTime();
		  
	 	DF1.setTimeZone(TimeZone.getTimeZone("UTC"));
		String UTCDateFormat = DF1.format(startDate);
		return UTCDateFormat;
	}
	private static String firstDateCETToUTCFormat(String firstDate) throws ParseException {
		SimpleDateFormat DF = new SimpleDateFormat("yyyy-MM-dd");
		DF.setLenient(true);
		DF.setTimeZone(TimeZone.getTimeZone("CET"));
		
		SimpleDateFormat DF1 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
		
		Date startDate = DF.parse(firstDate);
		
		DF1.setTimeZone(TimeZone.getTimeZone("UTC"));
		String UTCDateFormat = DF1.format(startDate);
		
		return UTCDateFormat;
	}
	private static String convertUTCToCET(String UTCDate) {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
		Date date = null;
		try {
			date = formatter.parse(UTCDate.substring(0, UTCDate.length()));
		} catch (ParseException e1) {
			e1.printStackTrace();
		}
		SimpleDateFormat FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm");
		String dateValue = FORMATTER.format(date);
		
		SimpleDateFormat DF = new SimpleDateFormat("yyyy-MM-dd HH:mm");
		DF.setLenient(true);
		DF.setTimeZone(TimeZone.getTimeZone("UTC"));
		SimpleDateFormat DF1 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
		Date startDate = null;
		try {
			startDate = DF.parse(dateValue);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		DF1.setTimeZone(TimeZone.getTimeZone("CET"));
		String CETDateFormat = DF1.format(startDate);
		return CETDateFormat;
	}
	
	private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss");
	public static Date stringToDate(String date) throws ParseException {
		sdf.setTimeZone(TimeZone.getTimeZone("CET"));
		return sdf.parse(date);
	}
	public static String dateTimeinCET(Date date) {
		sdf.setTimeZone(TimeZone.getTimeZone("CET"));
		return sdf.format(date);
	}
	public static Date stringToDate(SimpleDateFormat sdf, String date) throws ParseException {
		sdf.setTimeZone(TimeZone.getTimeZone("CET"));
		return sdf.parse(date);
	}
	
	public static Timestamp getTimeStamp(Date date) {
		//Date dbResponseTime = new java.util.Date();
		Timestamp timestamp = new java.sql.Timestamp(date.getTime());
		System.out.println("Timestamp :"+ timestamp);
		return timestamp;
	}
	
	public static synchronized Date numberFormatEx(Date date) {
		String onlyTimeStr = sdf.format(date);  // line #5
		Date onlyTimeDt = null;
		try {
			onlyTimeDt = sdf.parse(onlyTimeStr);  // line #8
		} catch (ParseException ex) { 
			// can never happen (you would think!)
		}
		System.out.println("Date :"+ onlyTimeDt);
		return onlyTimeDt;
	}
	
	// ORACLE supports till 9999 - 10000 leads Year out of range
	public static void javaUtilSQlDates(String dateStr) throws ParseException {
		System.out.println("STR Date: "+dateStr);
		Date utilDate = stringToDate(dateStr);
		System.out.println("Get Time: "+ utilDate.getTime()); // 1581748586000
		getTimeStamp(utilDate); // Timestamp :2020-02-15 07:36:26.0
		
		// year the year minus 1900; must be 0 to 8099. (Note that 8099 is 9999 minus 1900.)
		// new Date(date.getYear() - 1900, date.getMonthValue() -1, date.getDayOfMonth());
		java.sql.Date sqlDate = new java.sql.Date( utilDate.getTime() );
		System.out.println("SQL Date: "+sqlDate);
	}
	
	public static void displayCETtoUTC(String firstDate, String lastDate) throws ParseException {
		SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd");
		String firstDateUTCFormat = firstDateCETToUTCFormat(firstDate);
		String lastDateUTCFormat = lastDateCETToUTCFormat(lastDate);
		
		System.out.format("UTC= First:%s, Last:%s\n", firstDateUTCFormat, lastDateUTCFormat);
	}
	
	public static Date addDays_OLD(Date date, int days) {
		long MSSEC_PERE_DAY = 1000 * 60 * 60 * 24;
		long MSSEC_PERE_HOUR = 1000 * 60 * 60;
		
		// remember hour of day
		int oldHours = date.getHours();
		
		// add days + 1 hour (for time shift)
		long goal = date.getTime() + MSSEC_PERE_DAY * days + MSSEC_PERE_HOUR;
		Date goalDate = new Date(goal);
		
		// reset hours of day (XXX addDays() will only work for hours < 23)
		goalDate.setHours(oldHours);
		return goalDate;
	}
	
	/**
	 * Add whole days to dates. When given negative values, days are subtracted.
	 * 
	 * @param date the date which will be used for calculations
	 * @param days the amount of days to be added (subtracted if negative)
	 * @return the new date having <code>days</code> added and possibly other
	 *         fields adjusted (28.2.2005+2d = 2.3.2005)
	 */
	public static Date addDays(Date date, int days) {
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		calendar.add(Calendar.DATE, days);
		
		return calendar.getTime();
	}
	//@Deprecated int getMonth() { return normalize().getMonth() - 1; // adjust 1-based to 0-based }
	//@param month the value used to set the {@code MONTH} calendar field in the calendar.
	// * Month value is 0-based. e.g., 0 for January.
	public static int getMonth(Date date) { // JAN:0, FEB:1, ... DEC:11
		Calendar cal = Calendar.getInstance();
		cal.setTime(date);
		int month = cal.get(Calendar.MONTH); // class GregorianCalendar extends Calendar
		//System.out.println("Month:"+month);
		return month;
	}
	public static int getYear(Date date) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(date);
		int year = cal.get(Calendar.YEAR); // class GregorianCalendar extends Calendar
		//System.out.println("Year:"+year);
		return year;
	}
	
	/*public static String changeDateFormat(String aDate, String dateFormat, String changeFormat) throws ParseException {
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("IST"));
		Date date = DateHelper.parseDate(aDate, dateFormat);
		String newForamtDate = DateHelper.formatDate(date, changeFormat, c); // "20.11.2008"
		System.out.println("Change Format Form:"+aDate+", To:"+newForamtDate);
		return newForamtDate;
	}*/
	
	public static LocalDateTime getRecentQuater() {
		// https://stackoverflow.com/questions/3553964/how-to-round-time-to-the-nearest-quarter-hour-in-java
		LocalDateTime time = LocalDateTime.now();
		LocalDateTime lastQuarter = time.truncatedTo(ChronoUnit.HOURS).plusMinutes(15 * (time.getMinute() / 15));
		System.out.println("lastQuarter: " + lastQuarter);
		return lastQuarter;
	}
	public static String getSysDate_LastQuarterMins(String dateFormat) {
		LocalDateTime lastQuarter = getRecentQuater();
		// https://stackoverflow.com/questions/19431234/converting-between-java-time-localdatetime-and-java-util-date
		Date date = Date.from(lastQuarter.atZone(ZoneId.systemDefault()).toInstant());
		SimpleDateFormat ft = new SimpleDateFormat (dateFormat);
		String sysDate_RoundMin = ft.format(date);
		System.out.println("getSysDate_LastQuarterMins() : "+sysDate_RoundMin);
		return sysDate_RoundMin;
	}
	
	// https://docs.oracle.com/javase/tutorial/i18n/format/simpleDateFormat.html
	static String formatStr = "dd/MM/yyyy";
	static DateFormat dateFormat = new SimpleDateFormat(formatStr);
	static DateFormat reverseDateFormat = new SimpleDateFormat("yyyy/MM/dd");
	
	public static String getSysDate_PlusMin(int longMills, String dateFormat) {
		Date sysDate = new Date(System.currentTimeMillis() + longMills);
		SimpleDateFormat ft = new SimpleDateFormat (dateFormat);
		String sysDate_PlusMin = ft.format(sysDate);
		System.out.println("getSysDate_PlusMin() : "+sysDate_PlusMin);
		return sysDate_PlusMin;
	}
	public static Date addDaysToDate(String specificDate, int daysCount) throws ParseException {
		Date date = dateFormat.parse(specificDate);
		GregorianCalendar gregCal = (GregorianCalendar) GregorianCalendar.getInstance(); // Current Date
		gregCal.setTime(date); // Change the Date to Provided One
		gregCal.add(Calendar.DAY_OF_YEAR, daysCount);
		Date time = gregCal.getTime();
		
		ZonedDateTime zdt = gregCal.toZonedDateTime();
		System.out.println("GregorianCalendar DayofWeek: "+ zdt.getDayOfWeek());
		return time;
	}
	public static String addDaysToDateStr(String specificDate, int daysCount) throws ParseException {
		String format = dateFormat.format( addDaysToDate(specificDate, daysCount) );
		System.out.println("GregorianCalendar [To a Date added Number of days leads to New Date]: "+ format);
		return format;
	}
	public static Date parseDate(String aSource, String formatStr) throws ParseException {
		DateFormat dateFormat = new SimpleDateFormat(formatStr);
		dateFormat.setLenient(false);
		return dateFormat.parse(aSource);
	}
	public static String formatDate(Date aDate, String formatStr, Calendar calendar) {
		DateFormat dateFormat = new SimpleDateFormat(formatStr);
		dateFormat.setLenient(false);
		dateFormat.setCalendar(calendar);
		return dateFormat.format(aDate);
	}
	public static String formatDate(Date aDate, String formatStr) {
		// http://tutorials.jenkov.com/java-date-time/parsing-formatting-dates.html
		DateFormat dateFormat = new SimpleDateFormat( formatStr );
		dateFormat.setLenient(false);
		//dateFormat.setCalendar(Calendar.getInstance(TimeZone.getTimeZone("UTF")));
		return dateFormat.format(aDate);
	}
	
	public int getTimeinSeconds(String timeStr) { // HH:MM
		String[] split = timeStr.split(":");
		int min = Integer.valueOf( split[0] );
		int sec = Integer.valueOf( split[1] );
		
		int total = ( (min * 60) + sec);
		System.out.println("TIME: "+ total );
		return total;
	}
	public boolean isTimeGreater(String timeStr, String timeStr2) {
		Integer timeinSeconds = getTimeinSeconds(timeStr);
		Integer timeinSeconds2 = getTimeinSeconds(timeStr2);
		
		if (timeinSeconds > timeinSeconds2) {
			System.out.println("T1 Greater than T2");
			return true;
		} else {
			System.out.println("T1 Less than T2");
			return false;
		}
	}
	
	/*public static int getDaysBetween(String startDateStr, String endDateStr) {
		// joda-time-2.10.1.jar, joda-convert-1.2.jar
		DateTimeFormatter formatter = org.joda.time.format.DateTimeFormat.forPattern("dd/MM/yyyy"); //  HH:mm:ss
		DateTime parseStartDateTime = formatter.parseDateTime(startDateStr);
		DateTime parseEndDateTime = formatter.parseDateTime(endDateStr);
		Days daysJoda = org.joda.time.Days.daysBetween( parseStartDateTime, parseEndDateTime );
		return daysJoda.getDays();
	}
	public static int getDaysBetween(Date startDate, Date endDate) {
		Calendar cal1 = Calendar.getInstance();
		Calendar cal2 = Calendar.getInstance();
		cal1.setTime(startDate);
		cal2.setTime(endDate);
		if (cal1.after(cal2)) { // swap dates so that d1 is start and d2 is end
			Calendar swap = cal1;
			cal1 = cal2;
			cal2 = swap;
		}
		int days = cal2.get(java.util.Calendar.DAY_OF_YEAR) - cal1.get(java.util.Calendar.DAY_OF_YEAR);
		int y2 = cal2.get(java.util.Calendar.YEAR);
		if (cal1.get(java.util.Calendar.YEAR) != y2) {
			cal1 = (java.util.Calendar) cal1.clone();
			do {
				days += cal1.getActualMaximum(java.util.Calendar.DAY_OF_YEAR);
				cal1.add(java.util.Calendar.YEAR, 1);
			} while (cal1.get(java.util.Calendar.YEAR) != y2);
		}
		return days;
	}
	
	public static int getTimeinSeconds(String timeStr) { // HH:MM
		String[] split = timeStr.split(":");
		int min = Integer.valueOf( split[0] );
		int sec = Integer.valueOf( split[1] );
		
		int total = ( (min * 60) + sec);
		System.out.println("TIME: "+ total );
		return total;
	}
	public static boolean isTimeGreater(String timeStr, String timeStr2) {
		Integer timeinSeconds = getTimeinSeconds(timeStr);
		Integer timeinSeconds2 = getTimeinSeconds(timeStr2);
		
		if (timeinSeconds > timeinSeconds2) {
			System.out.println("T1 Greater than T2");
			return true;
		} else {
			System.out.println("T1 Less than T2");
			return false;
		}
	}
	
	public static Date addDays(Date date, int days) {
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		calendar.add(Calendar.DATE, days);

		return calendar.getTime();
	}
	public static Date setDate(String dateStr) {
		Date currentDate = new Date();
		dateStr = dateStr.toUpperCase();
		dateStr = dateStr.replaceFirst("SYSDATE", "");
		
		if (!dateStr.equals("") && (dateStr.startsWith("-") || dateStr.startsWith("+"))) {
			currentDate = DateHelper.addDays(currentDate, Integer.parseInt(dateStr));
		}
		return currentDate;
	}*/
	
	public static void timeTaken(long startTime, long endTime) {
		long duration = (endTime - startTime);  
		System.out.format("Milli = %s, ( S_Start : %s, S_End : %s ) \n", duration, startTime, endTime );
		System.out.println("Human-Readable format : "+ millisToShortDHMS( duration ) );
	}
	public static String millisToShortDHMS(long duration) {
	    String res = "";    // java.util.concurrent.TimeUnit;
	    long days       = TimeUnit.MILLISECONDS.toDays(duration);
	    long hours      = TimeUnit.MILLISECONDS.toHours(duration) -
	                      TimeUnit.DAYS.toHours(TimeUnit.MILLISECONDS.toDays(duration));
	    long minutes    = TimeUnit.MILLISECONDS.toMinutes(duration) -
	                      TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(duration));
	    long seconds    = TimeUnit.MILLISECONDS.toSeconds(duration) -
	                      TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(duration));
	    long millis     = TimeUnit.MILLISECONDS.toMillis(duration) - 
	                      TimeUnit.SECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(duration));

	    if (days == 0)      res = String.format("%02d:%02d:%02d.%04d", hours, minutes, seconds, millis);
	    else                res = String.format("%dd %02d:%02d:%02d.%04d", days, hours, minutes, seconds, millis);
	    return res;
	}
	
	
	// -- APP Specific
	public static Timestamp convertDateToTimestamp(java.util.Date date) {
		return new Timestamp(date.getTime());
	}
	public static String formatSQLUTCDate(Date aDate)
	{
		StringBuffer b = new StringBuffer(getSQLUTCDateFormat().format(aDate));
		b.insert(b.length() - 2, ':');

		return b.toString();
	}
	static String SQLUTCDATEPATTERN_STR = "yyyy-MM-dd HH:mm Z";
	public static DateFormat getSQLUTCDateFormat()
	{
		DateFormat utcDateFormat = new SimpleDateFormat(SQLUTCDATEPATTERN_STR);
		utcDateFormat.setLenient(false);
		return utcDateFormat;
	}
	static final String DATEPATTERN_STR = "dd.MM.yyyy";
	public static String formatSQLDate(Date aDate)
	{
		DateFormat dateFormat = new SimpleDateFormat(DATEPATTERN_STR);
		dateFormat.setLenient(false);
		return dateFormat.format(aDate);
	}
	public static Date convertTimestampToDate(Timestamp timestamp)
	{
		long milliseconds = timestamp.getTime() + (timestamp.getNanos() / 1000000);
		return new java.util.Date(milliseconds);
	}
	
	
	/**
	 * the amount of milliseconds in one minute.
	 */
	public static final long MSECS_PER_MINUTE = (long)1000 * 60;

	/**
	 * the amount of milliseconds in one hour.
	 */
	public static final long MSECS_PER_HOUR = (long)1000 * 60 * 60;

	/**
	 * the amount of milliseconds in one day.
	 */
	public static final long MSECS_PER_DAY = (long)MSECS_PER_HOUR * 24;

	// Timezone & Locale for calculations
	/**
	 * the default Locale in this JVM.
	 */
	private static final Locale DEFAULT_LOCALE = Locale.getDefault();

	/**
	 * the default time zone this software is currently running in.
	 */
	private static final TimeZone DEFAULT_TIMEZONE = TimeZone.getDefault();

	public static final String DATEPATTERN_FILE="yyyyMMdd";

	/**
	 * defualt datebase return string representation for date
	 */
	private static final String DATEPATTERN_SLASH = "MM/dd/yyyy";

	/**
	 * Pattern String for UTC time format.
	 */
	private static final String UTCDATEPATTERN_STR = "yyyy-MM-dd'T'HH:mmZ";

	/**
	 * reverse String representation for a date.
	 */

	private static final String REVERSEDATEPATTERN_STR = "yyyy.MM.dd";

	/**
	 * private constructor, so class cannot be instantiated. Does nothing
	 */
	private DateHelper2()
	{
	}

	/**
	 * This method returns the default Locale used by date- and calendar-centric
	 * calculations. The locale is (amongst other things) responsible for
	 * default string formatting of date & time. Some of this behaviour is
	 * overridden by using Format Pattern explicit coded in this class.
	 * 
	 * @return the default locale set in this class
	 */
	public static Locale getDefaultLocale()
	{
		return DEFAULT_LOCALE;
	}

	/**
	 * This method returns the default TimeZone used by date- and
	 * calendar-centric calculations. Part of this TimeZone will be used when
	 * calculating the number of hours in a DateTimeRange. Within this
	 * calculation daylight savings will play an important role.
	 * 
	 * @return the default time zone set in this class
	 */
	public static TimeZone getDefaultTimeZone()
	{
		return DEFAULT_TIMEZONE;
	}



	/**
	 * @return the default pattern used when parsing a String for a date.
	 */
	public static String getDatePattern()
	{
		return DATEPATTERN_STR;
	}

	/**
	 * @return the pattern used when parsing Strings for a UTC date.
	 */
	public static String getUTCDatePattern() {
		return UTCDATEPATTERN_STR;
	}

	/**
	 * @return the default pattern used when dealing with SQL Strings as dates.
	 */
	public static String getSQLDatePattern() {
		return DATEPATTERN_STR;
	}
	
	
	/**
	 * default pattern used when dealing with SQL Strings as dates.
	 * @return
	 */

	public static String getDatepatternSlash() {
		return DATEPATTERN_SLASH;
	}

	/**
	 * @return the reverse date pattern.
	 */
	public static String getReverseDatePattern() {
		return REVERSEDATEPATTERN_STR;
	}

	/**
	 * @return the formatter used for parsing Strings for a date in UTC format.
	 */
	public static DateFormat getUTCDateFormat() {
		DateFormat utcDateFormat = new SimpleDateFormat(UTCDATEPATTERN_STR);
		utcDateFormat.setLenient(false);
		return utcDateFormat;
	}

	/**
	 * @return the formatter used for formating dates in reverse order.
	 */
	public static DateFormat getReverseDateFormat() {
		DateFormat reverseDateFormat = new SimpleDateFormat(REVERSEDATEPATTERN_STR);
		reverseDateFormat.setLenient(false);
		return reverseDateFormat;
	}

	/**
	 * this method takes a date and converts it to a String representation. The
	 * pattern used herein is specified by the internal date pattern.
	 * 
	 * @param aDate
	 *            the Date to be converted
	 * @return a String representation following the pattern
	 */
	public static String formatDate(Date aDate) {
		if (aDate == null) {
			return null;
		}
		
		DateFormat dateFormat = new SimpleDateFormat(DATEPATTERN_STR);
		dateFormat.setLenient(false);
		return dateFormat.format(aDate);
	}

	/**
	 * this method takes a date and converts it to a String representation
	 * according to the UTC date format. The pattern used herein is specified by
	 * the internal UTC date pattern.
	 * 
	 * @param aDate
	 *            the Date to be converted
	 * @return a String representation following the UTC pattern
	 */
	public static String formatUTCDate(Date aDate) {
		StringBuffer b = new StringBuffer(getUTCDateFormat().format(aDate));
		b.insert(b.length() - 2, ':');
		
		return b.toString();
	}

	/**
	 * @param aDate
	 *            the Date to be converted.
	 * @return a String representation with reverse order of day, month and
	 *         year.
	 */
	public static String formatReverseDate(Date aDate) {
		return getReverseDateFormat().format(aDate);
	}

	/**
	 * Parses a String for a Date, gives back a java.util.Date.
	 * 
	 * @param aSource
	 *            The String containing the date (without time)
	 * @return a Date object representing this date
	 * @throws ParseException
	 *             thrown if parsing fails
	 */
	public static Date parseDate(String aSource) throws ParseException {
		DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
		dateFormat.setLenient(false);
		return dateFormat.parse(aSource);
	}

	/**
	 * Create a Timestamp out of the two values, one for the date, the other for time.
	 * 
	 * @param date the date part for the timestamp.
	 * @param time the time part for the timestamp.
	 * @return a timestamp consisting of both date and time.
	 */
	public static Date combineDateAndTime(Date date, Date time) {
		GregorianCalendar timeCalendar = new GregorianCalendar();
		timeCalendar.setTime(time);
		
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		calendar.set(Calendar.HOUR_OF_DAY, timeCalendar.get(Calendar.HOUR_OF_DAY));
		calendar.set(Calendar.MINUTE, timeCalendar.get(Calendar.MINUTE));
		calendar.set(Calendar.SECOND, timeCalendar.get(Calendar.SECOND));
		calendar.set(Calendar.MILLISECOND, timeCalendar.get(Calendar.MILLISECOND));
		
		return calendar.getTime();
	}

	/**
	 * Cuts off the millis of a Date.
	 * 
	 * @param date
	 *            a Date with arbitrary values of millisecondes.
	 * @return a new Date having the millis set to 0
	 */
	public static Date trimDateToTime(Date date) {
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		calendar.set(Calendar.MILLISECOND, 0);
		
		return calendar.getTime();
	}

	/**
	 * Cuts off the time of a Date. In many places in Neon, dates are needed
	 * that have no time. To represent this, Date objects are used that have a
	 * time of 00:00:00.000. This method cuts off hours, minutes, seconds, and
	 * milliseconds.
	 * 
	 * @param date
	 *            a Date with arbitrary values of hours, minutes, seconds, and
	 *            millisecondes.
	 * @return a new Date having all fields of granularity smaller than days set
	 *         to zero.
	 */
	public static Date trimDateToDay(Date date) {
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		calendar.set(Calendar.HOUR_OF_DAY, 0);
		calendar.set(Calendar.MINUTE, 0);
		calendar.set(Calendar.SECOND, 0);
		calendar.set(Calendar.MILLISECOND, 0);

		return calendar.getTime();
	}

	/**
	 * Converts a java Date to an SQL Date. Due to its ugly mechanism of
	 * handling dates and - especially - sql.Date extending util.Date, date
	 * handling is very cumbersome in Java. Please _only_ use sql.Date for
	 * immediate database access!
	 * <p>
	 * Please be aware that the implementation of java.sql.Date is inconsistent.
	 * It stores the long integer as milliseconds right as java.util.Date does,
	 * but throws exceptions if trying to access hours, minutes, seconds, and
	 * milliseconds. But if you use the method <code>getTime()</code> to obtain
	 * the long integer value, these values forbidden in java.sql.Date are not
	 * set to zero, they are taken as is.
	 * 
	 * @param date
	 *            java.util.Date
	 * @return java.sql.Date
	 */
	public static java.sql.Date dateToSqlDate(Date date) {
		return java.sql.Date.valueOf(formatDate(date, "yyyy-MM-dd"));
	}

	/**
	 * Calculates the number of days between two calendar days in a manner which
	 * is independent of the Calendar type used. (see
	 * http://www.jguru.com/forums/view.jsp?EID=489372)
	 * 
	 * @param d1  The first date.
	 * @param d2  The second date.
	 * @return The number of days between the two dates. Zero is returned if the
	 *         dates are the same, one if the dates are adjacent, etc. The order
	 *         of the dates does not matter, the value returned is always >= 0.
	 *         If Calendar types of d1 and d2 are different, the result may not
	 *         be accurate.
	 */
	public static int getDaysBetween(Date d1, Date d2) {
		Calendar cal1 = Calendar.getInstance();
		Calendar cal2 = Calendar.getInstance();
		cal1.setTime(d1);
		cal2.setTime(d2);
		if (cal1.after(cal2))
		{ // swap dates so that d1 is start and d2 is end
			Calendar swap = cal1;
			cal1 = cal2;
			cal2 = swap;
		}
		int days = cal2.get(java.util.Calendar.DAY_OF_YEAR) - cal1.get(java.util.Calendar.DAY_OF_YEAR);
		int y2 = cal2.get(java.util.Calendar.YEAR);
		if (cal1.get(java.util.Calendar.YEAR) != y2) {
			cal1 = (java.util.Calendar) cal1.clone();
			do
			{
				days += cal1.getActualMaximum(java.util.Calendar.DAY_OF_YEAR);
				cal1.add(java.util.Calendar.YEAR, 1);
			}
			while (cal1.get(java.util.Calendar.YEAR) != y2);
		}
		return days;
	}

	/**
	 * Takes a date as String, parses it to assure it is a valid date and
	 * replaces the year by a four digit number if necessary. If it is not a
	 * valid date, the string is not modified.
	 * 
	 * @param stringDate
	 *            Input date as String.
	 * @return String date that has a four digit year.
	 */
	public static String fillUpStringDate(String stringDate) {
		// convert to date to check if it is a valid date
		try {
			parseDate(stringDate);
		} catch (ParseException e) {
			return stringDate;
		}
		String[] dayMonthYear = stringDate.split("\\.", Integer.MAX_VALUE);
		// day
		String day = dayMonthYear[0];
		if (day.length() == 1) {
			day = "0" + day;
		}
		// month
		String month = dayMonthYear[1];
		if (month.length() == 1) {
			month = "0" + month;
		}
		String year = dayMonthYear[2];
		if (year.length() == 1) {
			year = "200" + year;
		} else if (year.length() == 2) {
			year = "20" + year;
		} else if (year.length() == 3) {
			year = "2" + year;
		}
		stringDate = day + "." + month + "." + year;
		return stringDate;
	}

	public static Date addMinutes(Date date, int minutes) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(date);
		cal.add(Calendar.MINUTE, minutes);
		return cal.getTime();
	}

	/**
	 * To translate 12 hr time to 24 hr time
	 * 
	 * @param string
	 * @return String
	 */
	public static String convertTimeFormat(String time) {
		int index = time.indexOf(":");
		int hr = Integer.valueOf(time.substring(0, index)).intValue();
		String min = time.substring(index + 1, index + 3);

		if (time.indexOf("AM") != -1) {
			if (hr == 12) {
				hr = 0;
			}
			time = hr + ":" + min;
		}
		if (time.indexOf("PM") != -1) {
			if (hr != 12) {
				hr += 12;
			}
			time = hr + ":" + min;
		}
		return time;
	}
	
	// https://stackoverflow.com/questions/29026602/java-last-sunday-of-a-month
	public static Date getLastSunday( int month, int year ) {
		Calendar cal = Calendar.getInstance();
		cal.set( year, month + 1, 1 );
		cal.add(Calendar.DATE, -1); 
		cal.add( Calendar.DAY_OF_MONTH, -( cal.get( Calendar.DAY_OF_WEEK ) - 1 ) );
		return cal.getTime();
	}
}
