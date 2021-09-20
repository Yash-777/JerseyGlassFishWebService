package com.github.yash777.ftp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipInputStream;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.MediaType;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/* https://jsonformatter.curiousconcept.com/#
 * https://www.freeformatter.com/xml-formatter.html#ad-output
 */
public class LongDay_PayLoad2 {
	static String reqJson = 
			"[\r\n"
			+ "  {\r\n"
			+ "    \"timeStamp\":\"~!reqJSON!~ 05:02:18\",\r\n"
			+ "    \"objectType\":\"DEAL\",\r\n"
			+ "    \"objectSubType\":\"EXCH-PWR-PHYS\",\r\n"
			+ "    \"objectId\":\"~!OBJ!~\",\r\n"
			+ "    \"tranNum\":\"~!OBJ!~\",\r\n"
			+ "    \"versionNum\":1,\r\n"
			+ "    \"requestId\":null,\r\n"
			+ "    \"payLoad\":\"~!PAYLOAD!~\",\r\n"
			+ "    \"action\":1,\r\n"
			+ "    \"sourceSystemId\":\"L\",\r\n"
			+ "    \"messageData\":\"fuse_server={tradecapture-77bb99f65f-fsd2k}\",\r\n"
			+ "    \"objectLastUpdate\":\"~!reqJSON!~ 06:02:18\",\r\n"
			+ "    \"messageSent\":\"~!reqJSON!~ 05:02:18\",\r\n"
			+ "    \"recipientId\":null,\r\n"
			+ "    \"UpStreamRequestId\":null\r\n"
			+ "  }\r\n"
			+ "]";
	static String payloadXML = // Sell
			"<deal loss_factor=\"0\" last_update=\"~!PayLoadDate!~\" input_date=\"~!PayLoadDate!~\" ins_subtype=\"PWR Fixed-Price\" ins_type=\"EXCH-PWR-PHYS\" reference=\"EDRS.MyTrade.~!OBJ!~.S\" version_num=\"1\" tran_num=\"~!OBJ!~\" deal_num=\"~!OBJ!~\" scheduled=\"yes\" buy_sell=\"Sell\" status=\"New\" trade_date=\"~!PayLoadDate!~\">\r\n"
			+ "  <ext_bagent name=\"ECC_IDAY - BU\" id=\"22171\" />\r\n"
			+ "  <int_bunit name=\"ADC\" id=\"21037\" />\r\n"
			+ "  <ext_bunit name=\"ECC-BU\" id=\"20576\" />\r\n"
			+ "  <int_strategy name=\"MKT_ACCESS\" id=\"5141364\" />\r\n"
			+ "  <int_lentity name=\"XXXX Energy Trading\" id=\"20459\" />\r\n"
			+ "  <ext_lentity name=\"ECC_IDAY - BU\" id=\"22171\" />\r\n"
			+ "  <int_pfolio name=\"ASSET_POWERHEDGES\" id=\"20184\" />\r\n"
			+ "  <trader name=\"I4681\" id=\"\" />\r\n"
			+ "  <infos>\r\n"
			+ "    <info val=\"L\" key=\"system_id\" />\r\n"
			+ "    <info val=\"I4681\" key=\"Executing_trader\" />\r\n"
			+ "    <info val=\"no\" key=\"Automatic transmission\" />\r\n"
			+ "    <info val=\"~!PayLoadDate!~\" key=\"Orig Trade Date Time\" />\r\n"
			+ "    <info val=\"yes\" key=\"Scheduled\" />\r\n"
			+ "    <info val=\"EDRS.MyTrade.~!OBJ!~.S\" key=\"source_trade_id\" />\r\n"
			+ "    <info val=\"EPEX\" key=\"Exchange\" />\r\n"
			+ "    <info val=\"No\" key=\"OTC Cleared\" />\r\n"
			+ "    <info val=\"MyTrade\" key=\"deal_source\" />\r\n"
			+ "    <info val=\"TRD004\" key=\"XETRA_ID\" />\r\n"
			+ "    <info val=\"DE_GEN\" key=\"MyTrade_TEXT\" />\r\n"
			+ "    <info val=\"10712835630\" key=\"source_order_id\" />\r\n"
			+ "    <info val=\"10YDE-EON------1\" key=\"MyTrade_eic\" />\r\n"
			+ "  </infos>\r\n"
			+ "  <leg end_date=\"~!END!~\" price=\"12.4\" start_date=\"~!START!~\" unit=\"MWh\" time_zone=\"UTC\" ccy=\"EUR\">\r\n"
			+ "    <receipt_point name=\"HUB TENNETDE\" id=\"20039\" />\r\n"
			+ "    <profile>\r\n"
			+ "      <vol end=\"~!END!~\" price=\"12.4\" val=\"~!VOL!~\" start=\"~!START!~\" />\r\n"
			+ "    </profile>\r\n"
			+ "  </leg>\r\n"
			+ "</deal>";
	
	public static void main(String[] args) throws Exception {
		
		/*
		String userDir = System.getProperty("user.dir");
		System.out.println("userDir : "+userDir);
		
		String fileName = userDir+File.separator+"PayLoad.xml";
		File file = new File( fileName );
		// https://mvnrepository.com/artifact/com.google.guava/guava - r05
		//StringReader reader = new StringReader(file.getAbsolutePath());
		String text = com.google.common.io.Files.toString(file, com.google.common.base.Charsets.UTF_8);
		
		//DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		//builder.parse(text);
		
		//DOMParser parser = new DOMParser();
		//parser.parse(text);
		byte[] encoded = Base64.getEncoder().encode(text.getBytes());
		String encodedStr = new String(encoded, StandardCharsets.UTF_8);
		System.out.println("encodedStr : "+encodedStr);
		
		byte[] decoded = Base64.getDecoder().decode(encodedStr);
		String deocdedStr = new String(decoded, StandardCharsets.UTF_8);
		System.out.println("deocdedStr : "+deocdedStr);
		*/
		
		//System.setProperty("javax.net.debug", "all");
		
		String objectID =  "100077055194"; // ~!OBJ!~
		String startDate = "2021-10-31T01:00:00Z",
				endDate =  "2021-10-31T02:00:00Z",  // ~!START!~ , ~!END!~
				volume = "7"; // ~!VOL!~
		
		payloadXML = payloadXML.replaceAll("~!PayLoadDate!~", "2021-05-14T06:02:18");
		
		payloadXML = payloadXML.replaceAll("~!OBJ!~", objectID);
		payloadXML = payloadXML.replaceAll("~!START!~", startDate);
		payloadXML = payloadXML.replaceAll("~!END!~", endDate);
		payloadXML = payloadXML.replaceAll("~!VOL!~", volume);
		//System.out.println(payloadXML);
		
		reqJson = reqJson.replaceAll("~!reqJSON!~", "09-Jun-2021");
		reqJson = reqJson.replaceAll("~!OBJ!~", objectID);
		//byte[] decoded = Base64.getDecoder().decode(endStr);
		Encoder encoder = Base64.getEncoder();
		String encodeToString = encoder.encodeToString(payloadXML.getBytes());
		//System.out.println(encodeToString);
		reqJson = reqJson.replace("~!PAYLOAD!~", encodeToString);
		
		System.out.println(reqJson);
		
		boolean payloadValidation = false;
		
		if (payloadValidation) {
			String decryptedPayLoad = decodeAndUnzipString(encodeToString);
			System.out.println("Decrpted Payload: "+ decryptedPayLoad);
			
			Map<Long, String> payloadsMap = new HashMap<>();
			// Success
			payloadsMap.put(15500L, decryptedPayLoad);
			//payloadsMap.put(15515L, str2); // Failure
		
			validatePayLoadObj(payloadsMap);
		}
		
		String endpointUrl = "https://MyAppint.azure.MyAccount.energy:7775/MyTrade-MyApp-notifier-int/notifications/deals";
		
		File certFile = new File("./stackexchangeSSL.cer");
		InputStream certSSLStream = new FileInputStream(certFile);
		String aliaCertName = "MyAppint.azure.MyAccount.energy (MyAccount Internal Devices Sub CA V1)";
		
		serverDetails.put("OriginHost", "MyAppint.azure.MyAccount.energy:7775"); // javax.ws.rs.core.HttpHeaders.HOST
		serverDetails.put("Content-Request-Type", javax.ws.rs.core.MediaType.APPLICATION_JSON);
		sendHttpRestURLReq(endpointUrl, null, null, null, null, reqJson, certSSLStream, aliaCertName, null, serverDetails);
		
	}
	
	// Respose Reply: {"error_code":"TECHNICAL_ERROR","error_description":"Invalid mime type \", application/x-www-form-urlencoded\": Invalid token character ',' in token \", application\""}
	static HashMap<String, String> serverDetails = new HashMap<String, String>();
	static { // https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html
		serverDetails.put("OriginHost", ""); // javax.ws.rs.core.HttpHeaders.HOST
		serverDetails.put("User-Agent", "Apache-HttpClient/4.1.1 (java 1.5)");
		serverDetails.put("Accept-Encoding", "gzip,deflate");// ,sdch
		serverDetails.put("HTTP_ACCEPT_ENCODING", "gzip, deflate, br"); 
		serverDetails.put("ACCEPT_LANGUAGE", "en-US,en;q=0.9");
		serverDetails.put("Content-Request-Type", javax.ws.rs.core.MediaType.APPLICATION_JSON); //javax.ws.rs.core.MediaType.TEXT_PLAIN
		serverDetails.put("Content-Accept-Type", "text/*");
	}
	
	public static String sendHttpRestURLReq(String endpointUrl, String username, String password, String proxyHost, Integer proxyPort,
			String payLoad, InputStream certSSLStream, String aliaCertName, String certPassword, HashMap<String, String> serverDetails) throws IOException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException, TechnicalDeliveryException {
		
		String HTTP_METHOD = "POST"; // GET/POST
		String xmlRply = null ;
		
		HttpConnectionFactory httpConnectionFactory = null;
		if ( (proxyHost != null && proxyHost != "") && (proxyPort != null) ) {
			httpConnectionFactory = new HttpConnectionFactory(proxyHost, proxyPort);
		} else {
			httpConnectionFactory = new HttpConnectionFactory(null, null);
		}
		
		ClientBuilder newBuilder = javax.ws.rs.client.ClientBuilder.newBuilder();
		Client client = null;
		if (certSSLStream != null) {
			httpConnectionFactory.setClientCertificateStream(certSSLStream);
			
			if (aliaCertName != null && aliaCertName != "") {
				httpConnectionFactory.setCeritificateAlias(aliaCertName);
				
				Configuration clientConfig = httpConnectionFactory.getClientConfig();
				client = newBuilder
						.withConfig(clientConfig)
						.sslContext(httpConnectionFactory.getCertificateFactoryBasedSSLContext())
						.hostnameVerifier(httpConnectionFactory.getHostnameVerifier())
						.build();
			}
			if (certPassword != null && certPassword != "") {
				httpConnectionFactory.setClientCertificatePassword(certPassword);
				
				Configuration clientConfig = httpConnectionFactory.getClientConfig();
				client = newBuilder
						.withConfig(clientConfig)
						.sslContext(httpConnectionFactory.getKeyStoreBasedSSLContext())
						.hostnameVerifier(httpConnectionFactory.getHostnameVerifier())
						.build();
			}
		} else {
			client = newBuilder .build();
		}
		/*
		ServicePoint servicePoint = ServicePointManager.FindServicePoint(ex.Response.ResponseUri);
		if (servicePoint.ProtocolVersion < org.apache.http.HttpVersion.HTTP_1_1) {
			int maxIdleTime = servicePoint.MaxIdleTime;
			servicePoint.MaxIdleTime = 0;
			Thread.sleep(1);
			servicePoint.MaxIdleTime = maxIdleTime;
		}
		*/
		WebTarget jerseyWebTarget = client.target( endpointUrl );
		
		Invocation.Builder invocationBuilder = jerseyWebTarget.request(MediaType.WILDCARD)
				.header("Version", "HTTP/1.1"); // "*/*"
		javax.ws.rs.core.Response clientresponse = null;
		
		System.out.println("HTTP_METHOD :"+HTTP_METHOD);
		if (HTTP_METHOD.equals("POST")) {
			Entity<String> entity_Request = Entity.entity(payLoad, serverDetails.get("Content-Request-Type") );
			clientresponse = invocationBuilder.post(entity_Request);
		}
		if (HTTP_METHOD.equals("GET"))  clientresponse = invocationBuilder.get();
		
		int status = clientresponse.getStatus();
		String reasonPhrase = clientresponse.getStatusInfo().getReasonPhrase();
		System.out.println("javax.ws.rs.core.Response : \n" +clientresponse);
		System.out.println("javax.ws.rs.core.Response Status : " +status);
		System.out.println("javax.ws.rs.core.Response Status Info: " +reasonPhrase);
		
		MediaType mediaType_Response = clientresponse.getMediaType();
		System.out.println("javax.ws.rs.core.Response getMediaType(): " + mediaType_Response);
		
		String json_string_response = "";
		
		if (clientresponse.hasEntity()) {
			
			Object entity_Response = clientresponse.getEntity();
			System.out.println("javax.ws.rs.core.Response getEntity(): " + entity_Response);
			
			// org.glassfish.jersey.message.internal.MessageBodyProviderNotFoundException: MessageBodyReader not found for media type=application/json, type=interface java.util.Map, genericType=java.util.Map<java.lang.String, java.lang.String>.
			//Map<String, String> jsonMap = clientresponse.readEntity(new javax.ws.rs.core.GenericType<java.util.Map<String, String>>() {});
			//System.out.println("javax.ws.rs.core.GenericType jsonMap :"+jsonMap);
			
			if (mediaType_Response.toString().equals(javax.ws.rs.core.MediaType.APPLICATION_JSON) ) {
				System.out.println("Response.getType - APPLICATION_JSON");
				
// class org.glassfish.jersey.apache.connector.ApacheConnector$HttpClientResponseInputStream cannot be cast to class org.apache.http.HttpEntity 
				String json_string = clientresponse.readEntity(String.class);
						//org.apache.http.util.EntityUtils.toString( (HttpEntity) entity_Response );
				System.out.println("Entity<org.json.simple.JSONObject> :"+json_string);
				
			} else if (mediaType_Response.getType().equals(javax.ws.rs.core.MediaType.APPLICATION_XML) ) {
				System.out.println("Response.getType - APPLICATION_XML");
			} else if (mediaType_Response.getType().equals(javax.ws.rs.core.MediaType.APPLICATION_XHTML_XML) ) {
				System.out.println("Response.getType - APPLICATION_XHTML_XML");
			}
			
		}
		
		System.out.println("Final Response : "+ json_string_response);
		return null;
	}
	
	
	/*ZoneId zone = ZoneId.of("CET");
	System.out.println(zone);
	System.out.println(zone.getRules());*/
	/*for (ZoneOffsetTransition trans : zone.getRules().getTransitions()) {
	  System.out.println(trans);
	}*/
	/*CET
	ZoneRules[currentStandardOffset=+01:00]
	TransitionRule[Gap +01:00 to +02:00, SUNDAY on or after MARCH 25 at 02:00 STANDARD, standard offset +01:00]
	TransitionRule[Overlap +02:00 to +01:00, SUNDAY on or after OCTOBER 25 at 02:00 STANDARD, standard offset +01:00]*/
	/*for (ZoneOffsetTransitionRule rule : zone.getRules().getTransitionRules()) {
	  System.out.println(rule);
	}*/
	/*String s = "hi all ~!OBJ!~ you ~!OBJ!~ kk ~!OBJ!~";
	s = s.replaceAll("~!OBJ!~", "777");
	// Note that backslashes (\) and dollar signs ($) in the replacement string may cause the results to be different 
	System.out.println(s);
	*/	
	
	/*<dependency>
	<groupId>xerces</groupId> <artifactId>xercesImpl</artifactId> <version>2.12.0</version>
</dependency>*/
	static String UTCDATEPATTERN_STR = "yyyy-MM-dd'T'HH:mm";
	public static Date parseDate(String formatStr, String aSource) throws ParseException {
		SimpleDateFormat dateFormat = new SimpleDateFormat(formatStr);
		dateFormat.setLenient(true);
		Date date = dateFormat.parse(aSource);
		System.out.format("attribute [%s]= Date [%s]\n", aSource, date.toString());
		return date;
	}
	public static Date parseDateZone(String aSource) throws ParseException {
		String formatStr = "yyyy-MM-dd HH:mm:ss";
		SimpleDateFormat dateFormat = new SimpleDateFormat(formatStr, Locale.GERMANY);
		//dateFormat.setLenient(false);
		Date date = dateFormat.parse(aSource);
		System.out.format("attribute [%s]= Date [%s]\n", aSource, date.toString());
		return date;
	}
	
	public static boolean validatePayLoadObj(Map<Long, String> payloadsMap) throws Exception {
		Set<Long> payloadKeys = payloadsMap.keySet();
		Iterator<Long> iterator = payloadKeys.iterator();
		while (iterator.hasNext()) {
			org.apache.xerces.parsers.SAXParser parser = new org.apache.xerces.parsers.SAXParser();
			try {
				parser.setContentHandler(new org.xml.sax.helpers.DefaultHandler() {
					public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
						System.out.println("startElement:"+qName);
						if (qName.equalsIgnoreCase("deal")) {
							String lastUpdate = attributes.getValue("last_update");
							String inputDate = attributes.getValue("input_date");
							String tradeDate = attributes.getValue("trade_date");
							
							System.out.format("attributes lastUpdate[%s], inputDate[%s], tradeDate:[%s] \n", lastUpdate, inputDate, tradeDate);
							try {
								parseDate(UTCDATEPATTERN_STR, lastUpdate);
								parseDate(UTCDATEPATTERN_STR, inputDate);
								parseDate(UTCDATEPATTERN_STR, tradeDate);
							} catch (ParseException e) {
								e.printStackTrace();
							}
						}
						if (qName.equalsIgnoreCase("leg")) {
							String end_date = attributes.getValue("end_date");
							String start_date = attributes.getValue("start_date");
							System.out.format("attributes end_date[%s], start_date[%s] \n", end_date, start_date);
						}
						if (qName.equalsIgnoreCase("vol")) {
							String end = attributes.getValue("end");
							String start = attributes.getValue("start");
							System.out.format("attributes end[%s], start[%s] \n", end, start);
						}
					}
				});
				
				Long key = iterator.next();
				System.out.println("Key: "+ key);
				System.out.println("Val: "+ payloadsMap.get(key));
				Reader characterStream = new StringReader(payloadsMap.get(key));
				InputSource source = new InputSource( characterStream );
				System.out.println("source: "+ source);
				parser.parse(source); // [Fatal Error] :1:1: Content is not allowed in prolog.
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return true;
	}
	
	public static String decodeAndUnzipString(String endStr) throws IOException {
		String dealInString = null;
		byte[] decoded = Base64.getDecoder().decode(endStr);

		StringBuilder dealStringBuilder = new StringBuilder();
		InputStreamReader dealInputStreamReader = null;
		BufferedReader dealBufReader = null;
		ZipInputStream zipInputStream = null;
		ByteArrayInputStream inStream = null;

		try {
			inStream = new ByteArrayInputStream(decoded);
			zipInputStream = new ZipInputStream(inStream);

			String line = null;

			/** In case of UpStream --> MyApp we are receiving ZipInputStream */
			java.util.zip.ZipEntry eachEntry = zipInputStream.getNextEntry();
			if (eachEntry != null) {
				System.out.println("inside zip");
				dealInputStreamReader = new InputStreamReader(zipInputStream, StandardCharsets.UTF_8);
				dealBufReader = new BufferedReader(dealInputStreamReader);

				while (eachEntry != null) {
					while ((line = dealBufReader.readLine()) != null) {
						dealStringBuilder.append(line);
					}
					eachEntry = zipInputStream.getNextEntry();
				}
				dealInString = dealStringBuilder.toString();
			} else {
				dealInString = new String(decoded, StandardCharsets.UTF_8);
			}

			if (dealInString.trim().length() == 0) {
				dealInString = "--No Deal present after decryption--";
			}
		} catch (Exception e) {
			//log.error(e.toString(), e);
		} finally {
			if (dealBufReader != null) {
				dealBufReader.close();
			}
			
			if (dealInputStreamReader != null) {
				dealInputStreamReader.close();
			}
			
			if (zipInputStream != null) {
				zipInputStream.close();
			}
			
			if (inStream != null) {
				inStream.close();
			}
			
			dealStringBuilder = null;
			dealInputStreamReader = null;
			dealBufReader = null;
			zipInputStream = null;
			inStream = null;
		}
		return dealInString;
	}
}