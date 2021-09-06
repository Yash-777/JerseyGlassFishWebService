package org.github.common;

import java.text.ParseException;
import java.util.Date;

public class LongShort_DatesRange {
	public static void main(String[] args) throws ParseException {
		String formatStr = "yyyyMMddHHmm";
		
		// Short Day: 28/3 93, LongDay: 25/10 101 - Normal: 97
		int shortDayInterval = 92, longDayInterval = 100, dayInterval = 96;
		int minutesInterval = 15;
		int timeSeriesPperiodQuantitiesLength = dayInterval + 1;
		// "27-MAR-2021 00:00:00"  "25-OCT-2020 00:00:00"
		Date message_firstDate = DateHelper2.stringToDate("27-MAR-2021 00:00:00");
		String schIntFirst = DateHelper2.formatDate(message_firstDate, formatStr);
		System.out.println("---------------------- schIntFirst: "+schIntFirst);
		
		// Short Day Dates and Long Day dates
		Date schIntervall = DateHelper2.addMinutes(message_firstDate, (timeSeriesPperiodQuantitiesLength - 1) * minutesInterval * 2);
		System.out.println("----------------------  schIntLast: "+DateHelper2.formatDate(schIntervall, formatStr));
		schIntervall = DateHelper2.addDays(schIntervall, -1);
		
		String schIntLast = DateHelper2.formatDate(schIntervall, formatStr);
		System.out.println("----------------------  schIntLast: "+schIntLast);
		
		//@Deprecated int getMonth() { return normalize().getMonth() - 1; // adjust 1-based to 0-based }
		int month = DateHelper2.getMonth(message_firstDate);
		//System.out.println("Month:"+month);
		
		try {
			Date startDate_schIntFirst = DateHelper2.parseDate(schIntFirst, formatStr);
			Date endDate_schIntLast = DateHelper2.parseDate(schIntLast, formatStr);
			
			/*
			org.joda.time.DateTime startTime = new org.joda.time.DateTime(startDate_schIntFirst);
			org.joda.time.DateTime endTime = new org.joda.time.DateTime(endDate_schIntLast);
			org.joda.time.Period p = new org.joda.time.Period(startTime, endTime);
			int hours = p.getHours();
			System.out.println("JODA Diff:"+ hours);
			*/
			
			long secondsInMilli = 1000;
			long minutesInMilli = secondsInMilli * 60;
			long hoursInMilli = minutesInMilli * 60;
			
			int days = DateHelper2.getDaysBetween(startDate_schIntFirst, endDate_schIntLast);
			System.out.println("Days Difference: "+days +", month != 2:"+(month != 2));
			
			int MARCH = 2, OCTOBER = 9;
			if (days == 0 && (month == OCTOBER) ) { // Avoiding short day
				Date dateLongDayPrevious = DateHelper2.parseDate(schIntLast, formatStr);
				Date dateLongDayPrevious_Plus60min = DateHelper2.addMinutes(dateLongDayPrevious, 60);
				schIntLast = DateHelper2.formatDate(dateLongDayPrevious_Plus60min, formatStr);
				System.out.println("Logn Day Previous Day :: Schedule First:"+schIntFirst + ", Last :"+schIntLast);
			} else if ( month == MARCH ) { // MARCH: Short Day Previous Day
				System.out.println("March Month : Short Day on Last Sunday");
				
				//milliseconds
				long different_Milliseconds = endDate_schIntLast.getTime() - startDate_schIntFirst.getTime();
				long elapsedHours = different_Milliseconds / hoursInMilli;
				System.out.println("Diff:"+ elapsedHours);
				
				int year = DateHelper2.getYear(startDate_schIntFirst);
				Date lastSunday = DateHelper2.getLastSunday(MARCH, year);
				
				System.out.println("Last Sunday:"+ lastSunday.getDate() + ", Dates End:"+ endDate_schIntLast.getDate());
				
				if (elapsedHours > 24 && lastSunday.getDay() == endDate_schIntLast.getDay() ) {
					Date dateLongDayPrevious = DateHelper2.parseDate(schIntLast, formatStr);
					Date dateLongDayPrevious_Plus60min = DateHelper2.addMinutes(dateLongDayPrevious, -60);
					schIntLast = DateHelper2.formatDate(dateLongDayPrevious_Plus60min, formatStr);
					System.out.println("Short Day Previous Day :: Schedule First:"+schIntFirst + ", Last :"+schIntLast);
				}
			}
		} catch (ParseException e) {
			e.printStackTrace();
		}
		System.out.println("----------------------  schIntLast: "+schIntLast);
	}
}