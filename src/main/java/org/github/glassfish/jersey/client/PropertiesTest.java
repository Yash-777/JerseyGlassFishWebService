package org.github.glassfish.jersey.client;

import java.io.FileInputStream;
import java.util.Properties;


/** 
 * The setProperties method changes the set of system properties for the current running application.
 * These changes are not persistent. That is, changing the system properties within an application will
 *  not affect future invocations of the Java interpreter for this or any other application. 
 *  The runtime system re-initializes the system properties each time its starts up. If changes to 
 *  system properties are to be persistent, then the application must write the values to some file before 
 *  exiting and read them in again upon startup.
 *  <p>https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html</p>
 *  
 * @author Yashwanth Merugu
 *
 */
public class PropertiesTest {
	public static void main(String[] args) throws Exception {
		
		// set up new properties object from file "myProperties.txt"
		FileInputStream propFile = new FileInputStream( "./myProperties.txt");
		Properties p = new Properties(System.getProperties());
		p.load(propFile);
		
		// set the system properties
		System.setProperties(p);
		// display new properties
		System.getProperties().list(System.out);
		/*
		we use System.getProperty(“log_dir”) to read the value of the property log_dir. We also make use of the
		default value parameter so if the property does not exist, getProperty returns of /tmp/default/log
		*/
		String log_dir = System.getProperty("log_dir","/tmp/default/log");
		System.out.println("log_dir :"+log_dir);
	}
}
