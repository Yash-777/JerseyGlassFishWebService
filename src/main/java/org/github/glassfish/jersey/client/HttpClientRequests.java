package org.github.glassfish.jersey.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

public class HttpClientRequests {
	static Log log = LogFactory.getLog(Class.class);

	public static void main(String[] args) throws ClientProtocolException, IOException {
		log.warn("Logging Works");
		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");

		System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
		System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");

		Logger.getLogger("org.apache.http").setLevel(Level.ALL);
		Logger.getLogger("org.apache.http.wire").setLevel(Level.ALL);
		Logger.getLogger("org.apache.http.headers").setLevel(Level.ALL);
		
		DefaultHttpClient client = new DefaultHttpClient();

		HttpGet method = new HttpGet("http://www.google.com");
		method.setProtocolVersion(HttpVersion.HTTP_1_1);
		
		HttpResponse response = client.execute(method);
		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

		String line = "";
		while ((line = rd.readLine()) != null) {
			System.out.println(line);
		}
	}

}
