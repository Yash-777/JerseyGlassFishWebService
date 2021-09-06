package org.github.common;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;

// https://stackoverflow.com/questions/180158/how-do-i-time-a-methods-execution-in-java
public class TimeTakenToCompleteTask {
	public static void main(String[] args) {
		System.out.println("'User time' is the time spent running your application's own code.\r\n"
				+ "'System time' is the time spent running OS code on behalf of your application (such as for I/O).\r\n"
				+ "getCpuTime() method gives you sum of those:");
		
		long userTime = CPUUtils.getUserTime();
		long systemTime = CPUUtils.getSystemTime();
		long cpuTime = CPUUtils.getCpuTime();
		System.out.println("UserTime   : "+ userTime);
		System.out.println("SystemTime : "+ systemTime);
		System.out.println("CpuTime    : "+ cpuTime);
		System.out.println("SUM: "+ (userTime + systemTime) );
	}
}

class CPUUtils {
	/** Get CPU time in nanoseconds. */
	public static long getCpuTime() {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean();
		return bean.isCurrentThreadCpuTimeSupported() ? bean.getCurrentThreadCpuTime() : 0L;
	}

	/** Get user time in nanoseconds. */
	public static long getUserTime() {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean();
		return bean.isCurrentThreadCpuTimeSupported() ? bean.getCurrentThreadUserTime() : 0L;
	}

	/** Get system time in nanoseconds. */
	public static long getSystemTime() {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean();
		return bean.isCurrentThreadCpuTimeSupported()
				? (bean.getCurrentThreadCpuTime() - bean.getCurrentThreadUserTime())
				: 0L;
	}
}
