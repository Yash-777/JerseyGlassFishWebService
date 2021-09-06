package org.github.glassfish.jersey.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.SSLContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.http.HttpVersion;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

/**
 * https://docs.oracle.com/javaee/7/tutorial/jaxrs-client001.htm
 * 
 * Creating a Basic Client Request Using the Client API : https://docs.oracle.com/javaee/7/tutorial/jaxrs-client001.htm
 * 
 * Jersey 2.34 User Guide: https://eclipse-ee4j.github.io/jersey.github.io/documentation/latest/index.html
 * 
 * Jerser 1.x Client : https://docs.oracle.com/middleware/1213/wls/RESTF/develop-restful-client.htm#RESTF150
 * @author Yashwanth Merugu
 *
 */
public class StackOverFlow_JSON {
	private static Log commonsLog = org.apache.commons.logging.LogFactory.getLog(StackOverFlow_JSON.class);
	private static Logger utilLogger = Logger.getLogger(StackOverFlow_JSON.class.getName());
	
	org.apache.http.HttpVersion protocolVersion = org.apache.http.HttpVersion.HTTP_1_1;
	
	public static void getURLConnectionResponse(String urlStr) throws Exception {
		URL url = new URL("http://www.rgagnon.com/howto.html"); // https://stackoverflow.com/a/11093226/5081877
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestProperty("Accept-Encoding", "gzip");
		System.out.println("Length : " + con.getContentLength());
		// https://www.rgagnon.com/javadetails/java-HttpUrlConnection-with-GZIP-encoding.html
		Reader reader = null;
		if ("gzip".equals(con.getContentEncoding())) {
		 reader = new InputStreamReader(new GZIPInputStream(con.getInputStream()));
		} else {
			reader = new InputStreamReader(con.getInputStream());
		}
		
		while (true) {
			int ch = reader.read();
			if (ch==-1) break;
			System.out.print((char)ch);
		}
	}
	public static void main(String[] args) throws Exception {
		//https://api.stackexchange.com/2.2/users/{userid}?order=desc&sort=reputation&site=stackoverflow
		
		commonsLog.warn("Logging Works");
		
		// https://stackoverflow.com/a/49556107/5081877 : javax.net.ssl.SSLHandshakeException: Received fatal alert: protocol_version
		//System.setProperty("https.protocols", "TLSv1");
		
		// https://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#Debug
		// https://access.redhat.com/solutions/973783
		//System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
		//System.setProperty("javax.net.debug", "plaintext"); // all | ssl | ssl:handshake | ssl:record | ssl:keymanager:record
//		System.setProperty("log4j.logger.org.apache.http", "DEBUG");
//		System.setProperty("log4j.logger.org.apache.http.wire", "DEBUG");
//		System.setProperty("log4j.logger.org.apache.http.headers", "DEBUG");
		
		stackRequest();
		//getURLConnectionResponse("http://jquery.org");
		System.out.println("-------------------------------------------");
		
		/*
		Client client = javax.ws.rs.client.ClientBuilder.newClient();
		client.register(new org.glassfish.jersey.filter.LoggingFilter()); // Jersey 2x
		WebTarget myResource = client.target("https://api.stackexchange.com/2.2/users")
			.path("{userid}").resolveTemplate("userid", "581877")
			.queryParam("order", "desc")
			.queryParam("sort", "reputation")
			.queryParam("site", "stackoverflow");
		javax.ws.rs.core.Response clientresponse = myResource
				.request(MediaType.WILDCARD).accept(MediaType.APPLICATION_JSON).get();
		
		int status = clientresponse.getStatus();
		String reasonPhrase = clientresponse.getStatusInfo().getReasonPhrase();
		System.out.println("javax.ws.rs.core.Response : \n" +clientresponse);
		System.out.println("javax.ws.rs.vcore.Response Status : " +status);
		System.out.println("javax.ws.rs.core.Response Status Info: " +reasonPhrase);
		
		MediaType mediaType_Response = clientresponse.getMediaType();
		System.out.println("javax.ws.rs.core.Response getMediaType(): " + mediaType_Response);
		
		MultivaluedMap<String, Object> headers = clientresponse.getHeaders();
		Set<String> keySet = headers.keySet();
		for (Iterator iterator = keySet.iterator(); iterator.hasNext();) {
			String key = (String) iterator.next();
			System.out.println(key +" : "+ headers.get(key));
		}
		
		List<Object> encoding = headers.get("content-encoding");
		System.out.println("content-encoding List:"+encoding);
		
		Object entity_Response = clientresponse.getEntity();
		System.out.println("javax.ws.rs.core.Response getEntity(): " + entity_Response);
		
		// https://stackoverflow.com/questions/11093153/how-to-read-compressed-html-page-with-content-encoding-gzip
		String json_string = "";
		if ( encoding.contains("gzip") || encoding.contains("x-gzip") ) { // myResource.request(MediaType.WILDCARD).get();
			InputStream inputStream = clientresponse.readEntity(InputStream.class);
			BufferedReader in = new BufferedReader(new InputStreamReader(new GZIPInputStream(inputStream)));
			String inputLine;
			while ((inputLine = in.readLine()) != null){
				json_string+=inputLine+"\n";
			}
			in.close();
			System.out.println("https://en.wikipedia.org/wiki/HTTP_compression:\n"+ json_string);
		} else {
			json_string = clientresponse.readEntity(String.class);
			System.out.println("APPLICATION_JSON :"+json_string);
		}
		client.close();
		*/
		
		
		//GZIP_Util gzip = new GZIP_Util();
		//String deCompressedString = gzip.getDeCompressedString( org.apache.commons.io.IOUtils.toByteArray(json_string) );
		//System.out.println("DeCompressedString :"+deCompressedString);
		
		//HashMap<String, ByteArrayOutputStream> uncompressedGZIPBytes = gzip.unCompressCommons( IOUtils.toInputStream(json_string) );
		//System.out.println("Map:"+ uncompressedGZIPBytes);
		
	}
	// https://api.stackexchange.com/docs
	public static void stackRequest() throws IOException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException, TechnicalDeliveryException {
		//Logger.getLogger("org.apache.commons.httpclient").setLevel(Level.ALL); https://stackoverflow.com/a/4917055/5081877
		//Logger.getLogger("httpclient").setLevel(Level.ALL);
		
		// https://api.stackexchange.com/docs/users-by-ids#order=desc&sort=reputation&ids=581877&filter=default&site=stackoverflow&run=true
		String endpointUrl = "https://api.stackexchange.com/2.2/users/{userid}?order=desc&sort=reputation&site=stackoverflow";
		String userID = "581877";
		endpointUrl = endpointUrl.replace("{userid}", userID);
		
		commonsLog.info("Endpoint URL:"+endpointUrl);
		utilLogger.log(Level.INFO, "Endpoint URL:"+endpointUrl);
		
		// https://api.stackexchange.com/docs/users#order=desc&sort=reputation&inname=Yash&filter=default&site=stackoverflow&run=true
		//endpointUrl = "https://api.stackexchange.com/2.2/users?order=desc&sort=reputation&inname=Yash&site=stackoverflow";
		
		File certFile = new File("./stackexchangeSSL.cer");
		InputStream certSSLStream = new FileInputStream(certFile);
		String aliaCertName = "*.stackexchange.com (R3)";
		
		String jsonString = sendHttpRestURLReq_GET(endpointUrl, null, null, null, null, certSSLStream, aliaCertName, null, serverDetails);
		
		// Convert JSON string to Map - https://mkyong.com/java/how-to-convert-java-map-to-from-json-jackson/
		// com.fasterxml.jackson.core:jackson-databind:2.12.3 - https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind
		com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
		java.util.Map<String, Object> jsonString2Map = mapper.readValue(jsonString, new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {});
		jsonString2Map.put("User_KEY", "Yash");
		System.out.println("fasterxml HashMap:"+jsonString2Map);
		
		String json = mapper.writeValueAsString(jsonString2Map); // convert map to JSON string
		System.out.println("map to JSON string compact-print :"+json);
		json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonString2Map);
		System.out.println("map to JSON string  pretty-print :"+json);
		
		/*
		String strXMLFilename = "./PayLoad.xml";
		File input = new File(strXMLFilename);
		String soapxmLasString = FileUtils.readFileToString(input);
		//String content = new String(Files.readAllBytes(Paths.get("readMe.txt")), StandardCharsets.UTF_8);
		byte[] tsoBytes = soapxmLasString.trim().getBytes();
		String encodedStr = Base64.getEncoder().encodeToString(tsoBytes);
		System.out.println("Base64.getEncoder() :"+encodedStr);
		sendHttpRestURLReq_POST(endpointUrl, null, null, null, null, encodedStr, certSSLStream, null, certPassword, serverDetails);
		*/
	}
	
	static HashMap<String, String> serverDetails = new HashMap<String, String>();
	static { // https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html
		//utilLogger.setLevel(Level.ALL);
		
		serverDetails.put("OriginHost", ""); // javax.ws.rs.core.HttpHeaders.HOST
		serverDetails.put("User-Agent", "Apache-HttpClient/4.1.1 (java 1.5)");
		serverDetails.put("Accept-Encoding", "gzip,deflate");// ,sdch
		serverDetails.put("HTTP_ACCEPT_ENCODING", "gzip, deflate, br"); 
		
		serverDetails.put("ACCEPT_LANGUAGE", "en-US,en;q=0.9");
		
		serverDetails.put("Content-Request-Type", "text/plain;charset=UTF-8"); //javax.ws.rs.core.MediaType.TEXT_PLAIN
		serverDetails.put("Content-Accept-Type", "text/*"); // Accepted response type
	}
	
	public static Client getRestClient(String endpointUrl, String username, String password, String proxyHost, Integer proxyPort,
			InputStream certSSLStream, String aliaCertName, String certPassword, HashMap<String, String> serverDetails) throws KeyManagementException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, TechnicalDeliveryException, UnrecoverableKeyException {
		Client client = null;
		HttpConnectionFactory httpConnectionFactory = null;
		if ( (proxyHost != null && proxyHost != "") && (proxyPort != null) ) {
			httpConnectionFactory = new HttpConnectionFactory(proxyHost, proxyPort);
		} else {
			httpConnectionFactory = new HttpConnectionFactory(null, null);
		}
		SSLContext keyStoreBasedSSLContext = null;
		if (certSSLStream != null) {
			System.out.println("SSL HTTPS Connection...");
			httpConnectionFactory.setClientCertificateStream(certSSLStream);
			
			if (aliaCertName != null && aliaCertName != "") {
				httpConnectionFactory.setCeritificateAlias(aliaCertName);
				keyStoreBasedSSLContext = httpConnectionFactory.getCertificateFactoryBasedSSLContext();
			}
			if (certPassword != null && certPassword != "") {
				httpConnectionFactory.setClientCertificatePassword(certPassword);
				keyStoreBasedSSLContext = httpConnectionFactory.getKeyStoreBasedSSLContext();
			}
			
			Configuration clientConfig = httpConnectionFactory.getClientConfig();
			Client client_SSL = javax.ws.rs.client.ClientBuilder.newBuilder().withConfig(clientConfig)
					.sslContext(keyStoreBasedSSLContext)
					.hostnameVerifier(httpConnectionFactory.getHostnameVerifier())
					.build();
			client = client_SSL;
		} else {
			System.out.println("HTTP Connection...");
			Configuration clientConfig = httpConnectionFactory.getClientConfig();
			Client client_NonSSL = javax.ws.rs.client.ClientBuilder.newBuilder().withConfig(clientConfig)
					.hostnameVerifier(httpConnectionFactory.getHostnameVerifier()).build();
			client = client_NonSSL;
		}
		return client;
	}
	
	public static String sendHttpRestURLReq_GET(String endpointUrl, String loginUserName, String loginPassword, String proxyHost, Integer proxyPort,
			InputStream certSSLStream, String aliaCertName, String certPassword, HashMap<String, String> serverDetails) throws IOException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException, TechnicalDeliveryException {
		
		Client client = getRestClient(endpointUrl, loginUserName, loginPassword, proxyHost, proxyPort, certSSLStream, aliaCertName, certPassword, serverDetails);
		if ( (loginUserName != null && loginUserName != "") && (loginPassword != null && loginPassword != "") ) {
			HttpAuthenticationFeature feature = org.glassfish.jersey.client.authentication.HttpAuthenticationFeature.
					basic(loginUserName, loginPassword);
			client.register(feature);
		}
		//client.register(new org.glassfish.jersey.filter.LoggingFilter()); // Jersey 2x
		
		int connectionTimeoutMills = 10000;
		client.property(org.glassfish.jersey.client.ClientProperties.CONNECT_TIMEOUT, connectionTimeoutMills);
		client.property(org.glassfish.jersey.client.ClientProperties.READ_TIMEOUT, connectionTimeoutMills);
		
		WebTarget webTarget = client.target( endpointUrl );
		//webTarget = webTarget.path("service").queryParam("a", "avalue"); // https://cxf.apache.org/docs/jax-rs-client-api.html
		
		//org.glassfish.jersey.logging.LoggingFeature loggingFeature = new org.glassfish.jersey.logging.LoggingFeature(
		//		utilLogger, Level.ALL, org.glassfish.jersey.logging.LoggingFeature.Verbosity.PAYLOAD_ANY, 8192);
		//WebTarget register = webTarget.register(loggingFeature); // Jersey 1x
		
		
		
		//utilLogger.info("JerseyWebTarget Requesting URL :"+webTarget);
		Invocation.Builder invocationBuilder = webTarget.request(MediaType.WILDCARD); // "*/*"
				//.header("Version", "HTTP/1.1"); // HTTP/1.0
		// invocationBuilder = bilder.header("header1", "header value");
		
		//utilLogger.info("Invocation.Builder :"+invocationBuilder);
		javax.ws.rs.core.Response clientresponse = invocationBuilder.get();
		//utilLogger.info("Response :"+clientresponse);
		return getClientResponse(clientresponse);
	}
	
	public static String sendHttpRestURLReq_POST(String endpointUrl, String username, String password, String proxyHost, Integer proxyPort,
			String payLoad, InputStream certSSLStream, String aliaCertName, String certPassword, HashMap<String, String> serverDetails) throws IOException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException, TechnicalDeliveryException {
		
		Client client = getRestClient(endpointUrl, username, password, proxyHost, proxyPort, certSSLStream, aliaCertName, certPassword, serverDetails);
		WebTarget webTarget = client.target( endpointUrl );
		
		Invocation.Builder invocationBuilder = webTarget.request(MediaType.WILDCARD); // "*/*"
		//.header("Content-type", serverDetails.get("Content-Request-Type"));
		//webTarget.request(  ).accept( serverDetails.get("Content-Accept-Type") ); // status=500, reason=Internal Server Error
		// Req: webTarget.request("text/plain") -> Response:status=500, reason=Internal Server Error
		Entity<String> entity_Request = Entity.entity(payLoad, serverDetails.get("Content-Request-Type") );
		
		javax.ws.rs.core.Response clientresponse = invocationBuilder.post(entity_Request);
		return getClientResponse(clientresponse);
	}
	public static String getClientResponse(javax.ws.rs.core.Response clientresponse) throws JsonMappingException, JsonProcessingException {
		int status = clientresponse.getStatus();
		String reasonPhrase = clientresponse.getStatusInfo().getReasonPhrase();
		System.out.println("javax.ws.rs.core.Response : \n" +clientresponse);
		System.out.println("javax.ws.rs.core.Response Status : " +status);
		System.out.println("javax.ws.rs.core.Response Status Info: " +reasonPhrase);
		
		MediaType mediaType_Response = clientresponse.getMediaType();
		System.out.println("javax.ws.rs.core.Response getMediaType(): " + mediaType_Response);
		String response = "";
		if (clientresponse.hasEntity()) {
			
			Object entity_Response = clientresponse.getEntity();
			System.out.println("javax.ws.rs.core.Response getEntity(): " + entity_Response);
			
			// org.glassfish.jersey.message.internal.MessageBodyProviderNotFoundException: MessageBodyReader not found for media type=application/json, type=interface java.util.Map, genericType=java.util.Map<java.lang.String, java.lang.String>.
			//Map<String, String> jsonMap = clientresponse.readEntity(new javax.ws.rs.core.GenericType<java.util.Map<String, String>>() {});
			//System.out.println("javax.ws.rs.core.GenericType jsonMap :"+jsonMap);
			
			if (mediaType_Response.toString().contains(javax.ws.rs.core.MediaType.APPLICATION_JSON) ) {
				System.out.println("Response.getType - APPLICATION_JSON");
				
				// class org.glassfish.jersey.apache.connector.ApacheConnector$HttpClientResponseInputStream cannot be cast to class org.apache.http.HttpEntity 
				String json_string = clientresponse.readEntity(String.class);
						//org.apache.http.util.EntityUtils.toString( (HttpEntity) entity_Response );
				System.out.println("Entity<org.json.simple.JSONObject> :"+json_string);
				//json_string_response = json_string;
				
				// Convert JSON string to Map - https://mkyong.com/java/how-to-convert-java-map-to-from-json-jackson/
				// com.fasterxml.jackson.core:jackson-databind:2.12.3 - https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind
				
				com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
				//java.util.Map<String, String> map = mapper.readValue(json_string, java.util.Map.class);
				java.util.Map<String, Object> map = mapper.readValue(json_string, new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {});
				
				System.out.println("fasterxml HashMap:"+map);
				response = mapper.writeValueAsString(map); //map.toString();
			} else if (mediaType_Response.getType().contains(javax.ws.rs.core.MediaType.APPLICATION_XML) ) {
				System.out.println("Response.getType - APPLICATION_XML");
			} else if (mediaType_Response.getType().contains(javax.ws.rs.core.MediaType.APPLICATION_XHTML_XML) ) {
				System.out.println("Response.getType - APPLICATION_XHTML_XML");
			}
			
		}
		return response;
	}
	
	// urlStr: https://raw.githubusercontent.com/Yash-777/SeleniumWebDrivers/master/pom.xml
	// Stack POST Yash: https://stackoverflow.com/a/49556107/5081877
	public static String readCloudFileAsString( String urlStr ) throws java.io.IOException {
		if( urlStr != null && urlStr != "" ) {
			java.io.InputStream s = null;
			String content = null;
			try {
				URL url = new URL( urlStr );
				s = (java.io.InputStream) url.getContent();
				content = IOUtils.toString(s, "UTF-8");
			} finally {
				if (s != null) s.close(); 
			}
			return content.toString();
		}
		return null;
	}
}
