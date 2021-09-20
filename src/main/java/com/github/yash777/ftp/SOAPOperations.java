package com.github.yash777.ftp;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.json.simple.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

// https://www.soapui.org/docs/soapui-projects/ws-security/
@SuppressWarnings({"deprecation", "restriction"})
public class SOAPOperations {
	// https://github.com/mulderbaba/webservices-osgi/blob/7090b58bd4cdf5fab4af14d54cb20bb45c074de2/com/sun/xml/wss/impl/MessageConstants.java
	static class MessageConstants {
		public static final String 
		SOAP_1_1_NS = "http://schemas.xmlsoap.org/soap/envelope/",
		SOAP_1_2_NS = "http://www.w3.org/2003/05/soap-envelope",
		
		WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
		WSSE_PREFIX = "wsse",
		
		WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
		WSU_PREFIX = "wsu",
		
		DSIG_NS = "http://www.w3.org/2001/10/xml-exc-c14n#", // javax.xml.crypto.dsig.XMLSignature.XMLNS, Constants.SignatureSpecNS
		DSIG_PREFIX = "ds",
		
		WSS_SPEC_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0",
		BASE64_ENCODING_NS = WSS_SPEC_NS + "#Base64Binary",
		
		X509_TOKEN_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0",
		X509_NS = X509_TOKEN_NS + "#X509", X509v1_NS = X509_TOKEN_NS + "#X509v1", X509v3_NS = X509_TOKEN_NS + "#X509v3",
		X509SubjectKeyIdentifier_NS = X509_TOKEN_NS + "#X509SubjectKeyIdentifier",
		
		TRANSFORM_C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#" // Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS
		;
	}
	/*
Message Security
Each XML message should contain information in the header about the certificate used for signing the message. 
There are two fields required: the Issuing Body (CA) and the Serial Number of the certificate. The layout of this header 
is fixed. With this rule we are following official standards, a description of the standard can be found here
http://www.w3.org/TR/xmldsig-core/#sec-CoreSyntax (under reference [signing1]).


Only the payload of the message is signed (everything within the SOAP body), using the following specs:
 SignatureMethod – RSAwithSHA256		  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
 CanonicalizationMethod – xml-exc-c14n#   <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
 DigestMethod – xmlenc#sha256			 <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
 KeyInfo/X509Data – X509SKI (X509IssuerSerial has been deprecated)
	 */
	static final String 
	signatureMethod_Algo =  XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, // SignatureMethod.RSA_SHA1, org.jcp.xml.dsig.internal.dom.DOMSignatureMethod.RSA_SHA256,
	canonicalizationMethod_Algo = CanonicalizationMethod.EXCLUSIVE, // Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, http://www.w3.org/2001/10/xml-exc-c14n#"
	digestMethodAlog  =  DigestMethod.SHA256 //"http://www.w3.org/2001/04/xmlenc#sha256" // Constants.ALGO_ID_DIGEST_SHA1, org.apache.ws.security.handler.WSHandlerConstants.SIG_DIGEST_ALGO
	;

	static final String SOAP_PROTOCOL = SOAPConstants.SOAP_1_1_PROTOCOL;
	static String certEncodedID_KeyIdentifier_WsuID = "X509Token", timeStampID = "Timestamp", signedBodyID = "MsgBody";

	static boolean inclusiveNamespaceCanonicalization = true, inclusiveNamespaceTransform = true, useTimeStamp = false;
	/*
	<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" PrefixList="soapenv v1" />
	</ds:CanonicalizationMethod>

	<ds:Transforms>
		<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
			<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="v1" />
		</ds:Transform>
	</ds:Transforms>
	 */
	static String
	//canonicalizationPrefixListName = "soapenv v1 v11",
	transformPrefixListName = "v1 v11";

	static String path = "",  // "C:/Yash/Certs/",
		privateKeyFilePath = path+"Baeldung.p12", publicKeyFilePath = path+"Baeldung.cer", passwordPrivateKey = "password";
	
	static String bodyXML = "<tem:Add xmlns:tem=\"http://tempuri.org/\">\r\n"
			+ " <tem:intA>3</tem:intA>\r\n"
			+ " <tem:intB>4</tem:intB>\r\n"
			+ "</tem:Add>";
	static String fileLocation_BodyXML = "C:/Yash/Schedule_8591824041505_001.xml",
			fileLocation_SoapTemplate = "PayLoad_envelop_template.xml";
	
	// String soapEndpointUrl_Status = "https://sys.tqf.svc.tennet.nl/MMCHub/v1.0";
	static String outputFile = "C:/Yash/PayLoad_SOAPSigned.xml", // C:/Yash/Certs/bodyXML.xml
			soapEndpointUrl = "https://gist.github.com/",
			sslCertFile = "C:\\\\Yash\\\\SOAP_WorkSpace\\\\gitSSL.pfx",
			sslCertFilePasword = "XXXXX";
	static {
		if (Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
			System.out.println("JVM Installing BouncyCastle Security Providers to the Runtime");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} else {
			System.out.println("JVM Installed with BouncyCastle Security Providers");
		}
		
		try {
			String diskFile_Lines = getDiskFile_Lines(new File(fileLocation_BodyXML));
			bodyXML = diskFile_Lines;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public static String getDiskFile_Lines( File file ) throws IOException {
		StringBuffer text = new StringBuffer();
		FileInputStream fileStream = new FileInputStream( file );
		BufferedReader br = new BufferedReader( new java.io.InputStreamReader( fileStream ) );
		for ( String line; (line = br.readLine()) != null; )
			text.append( line + System.lineSeparator() );
		return text.toString();
	}
	
	public static X509Certificate loadPublicKeyX509(InputStream cerFileStream) throws CertificateException, NoSuchProviderException {
		CertificateFactory  certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(cerFileStream);
		return x509Certificate;
	}
	public static PrivateKey loadPrivateKeyforSigning(InputStream cerFileStream, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12"); //, "BC");
		keyStore.load(cerFileStream, password.toCharArray());
		
		Enumeration<String> keyStoreAliasEnum = keyStore.aliases();
		PrivateKey privateKey = null;
		String alias = null;
		if ( keyStoreAliasEnum.hasMoreElements() ) {
			alias = keyStoreAliasEnum.nextElement();
			if (password != null) {
				privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
				
				X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
				PublicKey publicKey = x509Certificate.getPublicKey();
				System.out.println("loadPublicKey : "+ publicKey);
				System.out.println("privateKey : "+privateKey);
				
				//loadPublicKeyX509 = x509Certificate; // Static PUBLIC Cert
			}
		}
		return privateKey;
	}

	static X509Certificate loadPublicKeyX509;
	static PrivateKey privateKey;
	
	/** https://www.w3.org/TR/xmldsig-core/#sec-X509Data
	 * https://www.ibm.com/docs/en/was-zos/9.0.5?topic=services-key-information
The key information types in the WS-Security bindings specify different mechanisms for referencing security tokens by using the
<wsse:SecurityTokenReference> element within the <ds:KeyInfo> element.
The following key information types are available in the WS-Security bindings:
	+ Security token reference [BinarySecurityToken - #X.509v3]
	  The X509Certificate element, which contains a base64-encoded [X509V3] certificate
	+ Key identifier		   [KeyIdentifier	   - #X509SubjectKeyIdentifier]
	  The X509SKI element, which contains the base64 encoded plain (i.e. non-DER-encoded) value of a X509 V.3 SubjectKeyIdentifier extension
	- X509 issuer name and issuer serial
	  The deprecated X509IssuerSerial element, which contains an X.509 issuer distinguished name/serial number pair.
	~ Embedded token
	~ Thumbprint (JAX-WS only)
	~ Key name (JAX-RPC only)
	*/
	
	static void loadCerts() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
		InputStream cerFileStream = getCerFileStream(true, publicKeyFilePath);
		loadPublicKeyX509 = loadPublicKeyX509(cerFileStream);
		PublicKey publicKey = loadPublicKeyX509.getPublicKey();
		System.out.println("loadPublicKey : "+ publicKey);
		
		InputStream pkcs_FileStream = getCerFileStream(true, privateKeyFilePath);
		privateKey = loadPrivateKeyforSigning(pkcs_FileStream, passwordPrivateKey);
	}
	/* An UUID is stated in 32 hexadecimal digits divided into five groups, in mismatch and separated by hyphens: 8-4-4-4-12. An UUID 
	is thus composed of 36 characters: 32 hexadecimal digits and four hyphens.	
	*/
	static UUID getUUID() {
		UUID randomUUID = UUID.randomUUID();
		System.out.println("UUID:"+ randomUUID); // 270200bc-f027-41ef-a8ac-35c7074fd25e
		return randomUUID;
	}
	
	enum WSSecurityBinding {
		BinarySecurityToken, SubjectKeyIdentifier, IssuerName_SerialNumber;
	}
	
	public static String getFileString(String xmlFilePath) throws IOException {
		File file = new File(xmlFilePath);
		//FileInputStream parseXMLStream = new FileInputStream(file.getAbsolutePath());
		
		java.util.Scanner scanner = new java.util.Scanner( file, "UTF-8" );
		String xmlContent = scanner.useDelimiter("\\A").next();
		scanner.close(); // Put this call in a finally block
		//System.out.println("Str:"+xmlContent);
		return xmlContent;
	}
	public static Document getDocument(String xmlData, boolean isXMLData) throws Exception {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setIgnoringComments(true);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc;
		if (isXMLData) {
			InputSource ips = new org.xml.sax.InputSource(new StringReader(xmlData));
			doc = dBuilder.parse(ips);
		} else {
			doc = dBuilder.parse( new File(xmlData) );
		}
		return doc;
	}
	public static SOAPMessage geSoapMessage(String inputFile, boolean isDataXML) throws Exception {
		
		SOAPMessage soapMsg;
		Document docBody = null;
		MessageFactory messageFactory = MessageFactory.newInstance(SOAP_PROTOCOL);
		if (isDataXML) {
			System.out.println("Sample DATA xml - Create SOAP Message");
			
			SOAPMessage soapMessage = messageFactory.createMessage();
			soapMsg = soapMessage;
			
			if (inputFile != null && inputFile != "") {
				String xmlContent = getFileString(inputFile);
				// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
				xmlContent=xmlContent.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
				docBody = getDocument(xmlContent.trim(), true);
				System.out.println("Data Document: "+docBody.getDocumentElement());
				dumpDOMDocument(docBody);
			}
		} else {
			System.out.println("SOAP XML with Envelope");
			if (inputFile != null && inputFile != "") {
				Document doc = getDocument(inputFile, false); // SOAP MSG removing comment elements
				String docStr = toStringDocument(doc); // https://stackoverflow.com/a/2567443/5081877
				ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(docStr.getBytes());
				
				MimeHeaders mimeHeaders = new MimeHeaders();
				// SOAPMessage message = MessageFactory.newInstance().createMessage(null, fileInputStream);
				SOAPMessage message = messageFactory.createMessage(mimeHeaders, byteArrayInputStream);
				soapMsg = message;
			} else {
				soapMsg = messageFactory.createMessage();
			}
			docBody = soapMsg.getSOAPBody().extractContentAsDocument();
			System.out.println("SOAP DATA Document: "+docBody.getDocumentElement());
		}
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		if (docBody != null) 
			soapBody.addDocument(docBody);
		
		soapMsg = getFinalSoapMessage(soapMsg);
		
		return soapMsg;
	}

	public static void main(String[] args) throws Exception {
		UUID uuid = getUUID();
		loadCerts();
		/*
		// https://stackoverflow.com/questions/65111989/java-signature-private-key-and-certificate-validation-fails
		String plainText = "Yash";
		java.security.Signature signAlog = java.security.Signature.getInstance("SHA256withRSA");
		
		//Sign
		signAlog.initSign(privateKey);
		signAlog.update(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		byte[] signature = signAlog.sign();
		System.out.println("Signature : "+ (new String(signature)));
		String result = java.util.Base64.getEncoder().encodeToString(signature);
		System.out.println("Signature Encoder: "+result);
		//Verify
		signAlog.initVerify(loadPublicKeyX509);
		signAlog.update(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		boolean bool = signAlog.verify(signature);
		System.out.println("VERIFIED: "+bool); //Always false
		*/
		test1();
		//test2();
		
		//getCertInfo(loadPublicKeyX509);
	}
	public static SOAPMessage getSoapMessage_File(String sopaEnvelopFile) throws Exception {
		Document doc = getDocument(sopaEnvelopFile, false); // SOAP MSG removing comment elements
		String docStr = toStringDocument(doc); // https://stackoverflow.com/a/2567443/5081877
		//docStr=docStr.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(docStr.getBytes());
		
		MimeHeaders mimeHeaders = new MimeHeaders();
		// SOAPMessage message = MessageFactory.newInstance().createMessage(null, fileInputStream);
		SOAPMessage message = MessageFactory.newInstance(SOAP_PROTOCOL).createMessage(mimeHeaders, byteArrayInputStream);
		
		return message;
	}
	public static void test1() throws Exception {
		SOAPMessage soapMessageEnv = getSoapMessage_File(fileLocation_SoapTemplate);
		soapMessageEnv = WS_Security_signature_KeyIdentifier(soapMessageEnv);
		
		SOAPPart soapPart = soapMessageEnv.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		Iterator namespacePrefixes = soapBody.getNamespacePrefixes();
		for (Iterator iterator = namespacePrefixes; iterator.hasNext();) {
			String prefix = (String) iterator.next();
			System.out.println("Prefix:"+prefix);
		}
		
		File certFile = new File(sslCertFile);
		InputStream certStream = new FileInputStream(certFile);
		SOAPOperations obj = new SOAPOperations();
		HashMap<String, String> serverDetails = obj.serverDetails;
		serverDetails.put("SOAPAction", "http://sys.svc.tennet.nl/MMCHub/listMessageMetadata");
		
		String soapMessageEnv_Str = getSoapMessage(soapMessageEnv);
		System.out.println("Final SOAP:\n"+ soapMessageEnv_Str);
		String statusResponse_Env = sendHttpURLReq(soapEndpointUrl, "", "", "", 0, soapMessageEnv_Str, certStream, "",
				sslCertFilePasword, serverDetails);
		
		System.out.println("statusResponse_Env:"+statusResponse_Env);
	}
	public static void test2() throws Exception {
		MessageFactory messageFactory = MessageFactory.newInstance(SOAP_PROTOCOL);
		SOAPMessage soapMsgTemp = messageFactory.createMessage();
		
		soapMsgTemp = getSOAPMessagefromHeaderDataXML(soapMsgTemp);
		SOAPMessage soapMsg = getSOAPMessagefromBodyDataXML(soapMsgTemp, bodyXML);
		System.out.println("SOAP:\n"+ getSoapMessageFromStream( soapMsg ));
		System.out.println("Final SOAP:\n"+ getSoapMessageFromStream( getFinalSoapMessage(soapMsg) ));
		
		WSSecurityBinding keyIdentifier = WSSecurityBinding.BinarySecurityToken;
		
		SOAPMessage finalSoapMsg;
		switch (keyIdentifier) {
		case BinarySecurityToken:
			//BinarySecurityToken: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3
			SOAPMessage ws_Security_signature_BinarySecurityToken = WS_Security_signature_BinarySecurityToken(soapMsg);
			finalSoapMsg = ws_Security_signature_BinarySecurityToken;
			System.out.println("WSS Binary Security Tocken Reference:\n"+getSoapMessage(ws_Security_signature_BinarySecurityToken));
			break;
		case SubjectKeyIdentifier:
			// Certificate Must not be self signed. It must be issued by CA [qualified certificate for electronic seal]
			SOAPMessage ws_Security_signature_KeyIdentifier = WS_Security_signature_KeyIdentifier(soapMsg);
			finalSoapMsg = ws_Security_signature_KeyIdentifier;
			System.out.println("WSS Key Identifier:\n"+getSoapMessage(ws_Security_signature_KeyIdentifier));
			break;
		case IssuerName_SerialNumber:
			SOAPMessage ws_Security_signature_IssuerSerial = WS_Security_signature_IssuerName_and_SerialNumber(soapMsg);
			finalSoapMsg = ws_Security_signature_IssuerSerial;
			System.out.println("WSS X509 issuer name and issuer serial:\n"+getSoapMessage(ws_Security_signature_IssuerSerial));
			break;
		}
		
		String soapMessageStr = getSoapMessage(soapMsg);
		System.out.println("SoapMessage String: "+soapMessageStr);
		try (
		  FileWriter fw = new FileWriter(outputFile)) {
		  fw.write(soapMessageStr);
		} catch (Exception e) {
		  throw new RuntimeException(e);
		}
		
		File certFile = new File(sslCertFile);
		InputStream certStream = new FileInputStream(certFile);
		SOAPOperations obj = new SOAPOperations();
		HashMap<String, String> serverDetails = obj.serverDetails;
		sendHttpURLReq(soapEndpointUrl, "", "", "", 0, soapMessageStr, certStream, "", "gitSSLPassword", serverDetails);
	}
	
	public static TBSCertificateStructure getCertInfo(X509Certificate cert) throws CertificateEncodingException, IOException {
		
		byte[] authorityInfoAccess = loadPublicKeyX509.getExtensionValue(Extension.authorityInfoAccess.getId());
		byte[] certificatePolicies = loadPublicKeyX509.getExtensionValue(Extension.certificatePolicies.getId());
		if (authorityInfoAccess != null && certificatePolicies != null) {
			System.out.println("authorityInfoAccess : "+ new String(authorityInfoAccess, "UTF-8") );
			System.out.println("certificatePolicies : "+ new String(certificatePolicies, "UTF-8") );
		} else {
			System.out.println("authorityInfoAccess : "+authorityInfoAccess);
			System.out.println("certificatePolicies : "+certificatePolicies);
		}
		//System.out.println("authorityInfoAccess : "+ authorityInfoAccess != null?(new String(authorityInfoAccess)):"Empty" );
		
		byte[] encoded = cert.getEncoded();
		ByteArrayInputStream bIn = new ByteArrayInputStream(encoded); // Public Key Encoded.
		ASN1InputStream aIn = new ASN1InputStream(bIn);
		ASN1Sequence asn1Sequence = (ASN1Sequence) aIn.readObject();
		//String dump = ASN1Dump.dumpAsString(seq);
		X509CertificateStructure obj = new X509CertificateStructure(asn1Sequence);
		TBSCertificateStructure tbsCert = obj.getTBSCertificate();
		
		System.out.println("X509CertificateStructure Issuer:"+tbsCert.getIssuer());
		System.out.println(" Subject:"+tbsCert.getSubject().toString());
		System.out.println(" SerialNumber:"+tbsCert.getSerialNumber());
		
		return tbsCert;
	}
	public static SOAPMessage WS_Security_signature_IssuerName_and_SerialNumber(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
//		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
//		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		//soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		//soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		securityElement.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		securityElement.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		SOAPElement X509Data = securityTokenReference.addChildElement("X509Data", MessageConstants.DSIG_PREFIX, MessageConstants.DSIG_NS);
		SOAPElement X509IssuerSerial = X509Data.addChildElement("X509IssuerSerial", MessageConstants.DSIG_PREFIX);
		
		SOAPElement X509IssuerName = X509IssuerSerial.addChildElement("X509IssuerName", MessageConstants.DSIG_PREFIX);
		X509IssuerName.addTextNode( getCertInfo(loadPublicKeyX509).getIssuer().toString() );
		
		SOAPElement X509SerialNumber = X509IssuerSerial.addChildElement("X509SerialNumber", MessageConstants.DSIG_PREFIX);
		X509SerialNumber.addTextNode( getCertInfo(loadPublicKeyX509).getSerialNumber().toString() );
		
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			String[] split = transformPrefixListName.split(" ");
			for (String string : split) {
				System.out.println("Transform Prefix:"+string);
				prefixList.add(string);
			}
			prefixList.add(transformPrefixListName);
			
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}
			
		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			Iterator namespacePrefixes = soapEnv.getNamespacePrefixes();
			for (Iterator iterator = namespacePrefixes; iterator.hasNext();) {
				String prefix = (String) iterator.next();
				System.out.println("InclusiveNamespaceCanonicalization Key:"+prefix);
				prefixList.add(prefix);
			}
			
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}
	
	// https://security.stackexchange.com/questions/200295/the-difference-between-subject-key-identifier-and-sha1fingerprint-in-x509-certif
	public static String getX509v3SubjectKeyIdentifier_CertEncoded(X509Certificate cert) throws IOException, CertificateEncodingException {
		// https://github.com/mulderbaba/webservices-osgi/blob/7090b58bd4cdf5fab4af14d54cb20bb45c074de2/com/sun/xml/wss/core/reference/X509SubjectKeyIdentifier.java#L108
		String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14", Authority_KEY_IDENTIFIER_OID = "2.5.29.35";
		byte[] subjectKeyIdentifier = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID); //  org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()
		System.out.println("X509SubjectKeyIdentifier ExtensionValue #"+subjectKeyIdentifier);
		if (subjectKeyIdentifier == null) {
			getCertInfo(cert);
			
			System.err.println("PKIX Certificate: Certificate is Self-Signed (or) CAs MUST mark this extension as non-critical. https://tools.ietf.org/html/rfc5280#page-28");
			// https://stackoverflow.com/a/31183447/5081877
			byte[] extensionValue = cert.getExtensionValue(Authority_KEY_IDENTIFIER_OID);
			System.out.println("Authority Key Identifier ExtensionValue #"+extensionValue);
			//byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
			//AuthorityKeyIdentifier authorityKeyIdentifier23 = AuthorityKeyIdentifier.getInstance(octets);
			//byte[] keyIdentifier = authorityKeyIdentifier23.getKeyIdentifier();
			
			throw new NullPointerException("SubjectKeyIdentifier OBJECT IDENTIFIER Value is Empty.");
		}
		sun.security.util.DerValue derVal = new sun.security.util.DerValue(
				new sun.security.util.DerInputStream(subjectKeyIdentifier).getOctetString());
		sun.security.x509.KeyIdentifier keyId = new sun.security.x509.KeyIdentifier(derVal.getOctetString());
		byte[] keyIDF = keyId.getIdentifier();
		String encodeToString = java.util.Base64.getEncoder().encodeToString(keyIDF);
		System.out.println("Subject Key Identifier Encoded Val: "+encodeToString );
		return encodeToString;
	}
	public static SOAPMessage WS_Security_signature_KeyIdentifier(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
//		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
//		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		//soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		//soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		securityElement.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		securityElement.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX);
		
		SOAPElement reference = securityTokenReference.addChildElement("KeyIdentifier", MessageConstants.WSSE_PREFIX);
		reference.setAttributeNS(null, "EncodingType", MessageConstants.BASE64_ENCODING_NS);
		reference.setAttributeNS(null, "ValueType", MessageConstants.X509SubjectKeyIdentifier_NS);
		reference.addTextNode( getX509v3SubjectKeyIdentifier_CertEncoded(loadPublicKeyX509) );
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		//String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		//XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
		
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI() );
		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			String[] split = transformPrefixListName.split(" ");
			for (String string : split) {
				System.out.println("Transform Prefix:"+string);
				prefixList.add(string);
			}
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}

		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			
			Iterator namespacePrefixes = soapEnv.getNamespacePrefixes();
			for (Iterator iterator = namespacePrefixes; iterator.hasNext();) {
				String prefix = (String) iterator.next();
				System.out.println("InclusiveNamespaceCanonicalization Key:"+prefix);
				prefixList.add(prefix);
			}
			/*
			String[] split = canonicalizationPrefixListName.split(" ");
			for (String string : split) {
				System.out.println("Canonicalization Prefix:"+string);
				prefixList.add(string);
			}
			*/	
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}
	
	HashMap<String, String> serverDetails = new HashMap<String, String>();
	{
		serverDetails.put("OriginHost", "");
		serverDetails.put("SoapWSDL", "");
		serverDetails.put("SoapBinding", "");
		serverDetails.put("MethodName", "");
		serverDetails.put("SOAPAction", ""); // Operation URL/Name to invoke.
		
		serverDetails.put("User-Agent", "Apache-HttpClient"); // Apache-HttpClient/4.1.1 (java 1.5)
		serverDetails.put("Accept-Encoding", "gzip,deflate,sdch");
		serverDetails.put("Content-Type", "text/xml;charset=UTF-8");
	}
	/* <!-- https://mvnrepository.com/artifact/org.glassfish.jersey.connectors/jersey-apache-connector -->
<dependency>
	<groupId>org.glassfish.jersey.connectors</groupId>
	<artifactId>jersey-apache-connector</artifactId>
	<version>3.0.2</version>
</dependency>
<dependency>
	<groupId>org.xooof.xmlstruct</groupId>
	<artifactId>xmlstruct</artifactId>
	<version>25.1.0.0</version>
</dependency>
	 */
	public static String sendHttpURLReq(String strUrl, String username, String password, String proxyHost, Integer proxyPort,
			String soapxmLasString, InputStream certSSLStream, String aliaCertName, String certPassword, HashMap<String, String> serverDetails) throws IOException {
		
		String xmlRply = null ;
		/*
		String strXMLFilename = "./SAOPRequest.xml";
		File input = new File(strXMLFilename);
		String soapxmLasString = FileUtils.readFileToString(input);
		//String content = new String(Files.readAllBytes(Paths.get("readMe.txt")), StandardCharsets.UTF_8);
		
		File certFile = new File("./github.com.crt"); // https://www.digicert.com/legal-repository
		InputStream certSSLStream = new FileInputStream(certFile);
		String aliaCertName = "DigiCert Global Root";
		String certPassword = "Git777"; // github.com.pfx
		*/
		HttpConnectionFactory httpConnectionFactory = null;
		if ( (proxyHost != null && proxyHost != "") && (proxyPort != null) ) {
			httpConnectionFactory = new HttpConnectionFactory(proxyHost, proxyPort);
		} else {
			httpConnectionFactory = new HttpConnectionFactory(null, null);
		}
		if (certSSLStream != null) {
			httpConnectionFactory.setClientCertificateStream(certSSLStream);
			
			if (aliaCertName != null && aliaCertName != "") httpConnectionFactory.setCeritificateAlias(aliaCertName);
			if (certPassword != null && certPassword != "") httpConnectionFactory.setClientCertificatePassword(certPassword);
		}
		
		URL url = new URL(null, strUrl);
		HttpURLConnection connection = (HttpsURLConnection) httpConnectionFactory.getHttpURLConnection(url);
		
		connection.setReadTimeout(5 * 1000);
		connection.setConnectTimeout(5 * 1000);
		connection.setDoInput(true);
		connection.setDoOutput(true);
		connection.setUseCaches(true);
		
		connection.setRequestMethod("POST");
		
		connection.setRequestProperty(javax.ws.rs.core.HttpHeaders.HOST, serverDetails.get("OriginHost")); // Origin: https://gist.github.com
		
		connection.setRequestProperty(javax.ws.rs.core.HttpHeaders.ACCEPT, "text/xml");
		connection.setRequestProperty(javax.ws.rs.core.HttpHeaders.ACCEPT_LANGUAGE, "en-US,en;q=0.9");
		
		connection.setRequestProperty("MethodName", serverDetails.get("MethodName") );
		connection.setRequestProperty("SOAPAction", serverDetails.get("SOAPAction") );
		
		connection.setRequestProperty("HTTP_ACCEPT_ENCODING", "gzip, deflate, br");
		connection.setRequestProperty("Accept-Encoding", serverDetails.get("Accept-Encoding"));
		
		//String soapxmLasString = getSoapMessage(request);
		connection.setRequestProperty(javax.ws.rs.core.HttpHeaders.CONTENT_TYPE, "text/xml");
		connection.setRequestProperty( "Content-Length", String.valueOf(soapxmLasString.length()));
		
//<dependency> <groupId>org.glassfish.jersey.connectors</groupId> <artifactId>jersey-apache-connector</artifactId> <version>3.0.2</version> </dependency>
//<dependency> <groupId>org.xooof.xmlstruct</groupId> <artifactId>xmlstruct</artifactId> <version>25.1.0.0</version> </dependency>
		if (username != null && username != "") { // Authorization: Basic ZW9uMDE5XzAxOkVsaWFfMTIz
			String authString = username + ":" + password;
			String authMsg = "Basic " + org.xooof.xmlstruct.Base64.encode(authString.getBytes());
			connection.setRequestProperty(javax.ws.rs.core.HttpHeaders.AUTHORIZATION, authMsg);
		}
		
		DataOutputStream printout = new DataOutputStream(connection.getOutputStream());
		try {
			printout.writeBytes(soapxmLasString);
		} finally {
			printout.close();
		}
		
		String contentEncoding = connection.getContentEncoding();
		System.out.println("Encoding:"+ contentEncoding);
		
		long start = System.currentTimeMillis();
		
		int responseCode = connection.getResponseCode();
		String responseMessage = connection.getResponseMessage();
		System.out.println("Response Code: " + responseCode + " " + responseMessage);
		
		String requestStatus = "Fail";
		if (responseCode == HttpURLConnection.HTTP_OK) {
			requestStatus = "Pass";
			
			InputStream inputStream = connection.getInputStream();
			xmlRply = getStreamContent(inputStream, contentEncoding);
		} else if (responseCode >= 400 && responseCode < 500) { // Response Code: 404 Not Found
			// getInputStream() = java.io.IOException: Server returned HTTP response code: 400 for URL
			InputStream inputStream = connection.getErrorStream();
			xmlRply = getStreamContent(inputStream, contentEncoding);
		} else if (responseCode >= 500) { // Response Code: 500 Internal Server Error
			// Exception in thread "main" java.io.IOException: Server returned HTTP response code: 500 for URL: https://graphical.weather.gov:443/xml/SOAP_server/ndfdXMLserver.php
			InputStream errorStream = connection.getErrorStream();
			xmlRply = getStreamContent(errorStream, contentEncoding);
		}
		
		long end = System.currentTimeMillis();
		String date = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(Calendar.getInstance().getTime());
		System.out.println("TIme taken Date:"+date+", TimeMillis:"+ (end-start));
		
		System.out.println("Respose Reply: " + xmlRply);
		System.out.println("Request Status:"+ requestStatus);
		
		return xmlRply;
	}

	public static String getStreamContent(InputStream input, String encoding) throws IOException {
		byte[] httpRply;
		String rply;
		httpRply = org.apache.commons.io.IOUtils.toByteArray(input);
		System.out.println("Byte Array:"+httpRply.toString());
		if (encoding == null) {
			rply = new String(httpRply);
		} else if ( encoding.equalsIgnoreCase("GZIP") ) { // https://stackoverflow.com/a/3627442/5081877
			rply = getGZIP(httpRply);
		} else { // "ISO-8859-1", ";TF-8"
			rply = new String(httpRply, encoding);
		}
		return rply;
	}
	public static String getGZIP(byte[] zipBytes) {
		try {
			GZIPInputStream gzipInput = new GZIPInputStream( new ByteArrayInputStream(zipBytes) );
			return org.apache.commons.io.IOUtils.toString(gzipInput);
		} catch (IOException e) {
			throw new UncheckedIOException("Error while decompression!", e);
		}
	}
	
	public static String getBinarySecurityToken_CertEncoded(X509Certificate cert) throws CertificateEncodingException {
		byte[] certByte = cert.getEncoded();
		String encodeToString = java.util.Base64.getEncoder().encodeToString(certByte);
		return encodeToString;
	}
	public static SOAPMessage WS_Security_signature_BinarySecurityToken(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add Binary Security Token. - <wsse:BinarySecurityToken EncodingType="...#Base64Binary" ValueType="...#X509v3" wsu:Id="X509Token">The base64 encoded value of the ROS digital certificate.</wsse:BinarySecurityToken>
		SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", MessageConstants.WSSE_PREFIX);
		binarySecurityToken.setAttribute("ValueType", MessageConstants.X509v3_NS);
		binarySecurityToken.setAttribute("EncodingType", MessageConstants.BASE64_ENCODING_NS);
		binarySecurityToken.setAttribute("wsu:Id", certEncodedID_KeyIdentifier_WsuID);
		binarySecurityToken.addTextNode( getBinarySecurityToken_CertEncoded(loadPublicKeyX509) );
		
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX);
		SOAPElement reference = securityTokenReference.addChildElement("Reference", MessageConstants.WSSE_PREFIX);
		reference.setAttribute("URI", "#"+certEncodedID_KeyIdentifier_WsuID); // <wsse:BinarySecurityToken wsu:Id="X509Token"
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			String[] split = transformPrefixListName.split(" ");
			for (String string : split) {
				System.out.println("Transform Prefix:"+string);
				prefixList.add(string);
			}
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}
			
		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			Iterator namespacePrefixes = soapEnv.getNamespacePrefixes();
			for (Iterator iterator = namespacePrefixes; iterator.hasNext();) {
				String prefix = (String) iterator.next();
				System.out.println("InclusiveNamespaceCanonicalization Key:"+prefix);
				prefixList.add(prefix);
			}
				
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}

	public static SOAPElement getTimeStamp(SOAPEnvelope soapEnv, SOAPElement securityElement) throws SOAPException {
		SOAPElement timestamp = null;
		int liveTimeInSeconds = 60;
		timestamp = securityElement.addChildElement("Timestamp", MessageConstants.WSU_PREFIX);
		timestamp.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), timeStampID);
			String DATE_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
			DateTimeFormatter timeStampFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN);
		timestamp.addChildElement("Created", MessageConstants.WSU_PREFIX).setValue(timeStampFormatter.format(ZonedDateTime.now().toInstant().atZone(ZoneId.of("UTC"))));
		timestamp.addChildElement("Expires", MessageConstants.WSU_PREFIX).setValue(timeStampFormatter.format(ZonedDateTime.now().plusSeconds(liveTimeInSeconds).toInstant().atZone(ZoneId.of("UTC"))));
		return timestamp;
	}

	public static String getSoapMessage(SOAPMessage soapMessage) throws Exception {
		SOAPEnvelope soapEnv = soapMessage.getSOAPPart().getEnvelope();
		Document ownerDocument = soapEnv.getOwnerDocument();
		String stringDocument = toStringDocument(ownerDocument);
		//System.out.println("SoapMessage: "+stringDocument);
		return stringDocument;
	}
	
	public static SOAPMessage getSOAPMessagefromHeaderDataXML(SOAPMessage soapMsg) throws Exception {
		SOAPEnvelope soapEnv = soapMsg.getSOAPPart().getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader();
		if (soapHeader == null) {
			soapHeader = soapEnv.addHeader();
			System.out.println("Provided SOAP XML does not contains any Header part. So creating it.");
		}
		
		String SCHEMA = "http://tempuri.org/", SCHEMA_PREFIX = "tem";
		
		soapHeader.addNamespaceDeclaration(SCHEMA_PREFIX, SCHEMA);
		QName qName = new QName(SCHEMA, "Add", SCHEMA_PREFIX);
		SOAPHeaderElement Add_Ele = soapHeader.addHeaderElement(qName);
		SOAPElement intA_Ele = Add_Ele.addChildElement("intA", SCHEMA_PREFIX);
		SOAPElement intB_Ele = Add_Ele.addChildElement("intB", SCHEMA_PREFIX);
		intA_Ele.setTextContent("3");
		intB_Ele.setTextContent("4");
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static SOAPMessage getSOAPMessagefromBodyDataXML(SOAPMessage soapMsg, String saopBodyXML) throws Exception {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setIgnoringComments(true);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		InputSource ips = new org.xml.sax.InputSource(new StringReader(saopBodyXML));
		Document docBody = dBuilder.parse(ips);
		System.out.println("Body Data Document: "+docBody.getDocumentElement());
		
		SOAPBody soapBody = soapMsg.getSOAPPart().getEnvelope().getBody();
		soapBody.addDocument(docBody);
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static String getSoapEnvelope_NamespacePrefixes(SOAPEnvelope soapEnv) {
		String prifixs = "";
		Iterator namespacePrefixes_soapEnv = soapEnv.getVisibleNamespacePrefixes();
		while (namespacePrefixes_soapEnv.hasNext()) {
			Object next = namespacePrefixes_soapEnv.next();
			System.out.println("SOAPEnvelope Prefix :"+ next);
			prifixs += next+ " ";
		}
		return prifixs.trim();
	}
	public static SOAPMessage getFinalSoapMessage(SOAPMessage soapMsg) throws SOAPException {
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		if (SOAP_PROTOCOL.equals("SOAP 1.1 Protocol") || SOAP_PROTOCOL.equals("SOAP 1.2 Protocol")) {
			System.out.println("SOAP 1.1 NamespaceURI: http://schemas.xmlsoap.org/soap/envelope/");
			System.out.println("SOAP 1.2 NamespaceURI: http://www.w3.org/2003/05/soap-envelope/");
			soapEnv.setPrefix("soapenv");
			soapEnv.removeNamespaceDeclaration("SOAP-ENV");
			soapEnv.removeNamespaceDeclaration("env"); // CHANGED
			soapHeader.setPrefix("soapenv");
			soapHeader.removeNamespaceDeclaration("SOAP-ENV");
			soapBody.setPrefix("soapenv");
			soapBody.removeNamespaceDeclaration("SOAP-ENV");
		}
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static String getSoapMessageFromStream(SOAPMessage soapMessage) throws Exception {
		java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
		soapMessage.writeTo(outputStream);
		String codepage = "UTF-8";
		String stringDocument = new String( outputStream.toByteArray(), codepage );
		//System.out.println("SoapMessage form Stram: "+stringDocument);
		return stringDocument;
	}

	public static InputStream getCerFileStream(boolean isClassPath, String fileName) throws FileNotFoundException {
		InputStream stream = null;
		if (isClassPath) {
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(fileName);
		} else {
			stream = new FileInputStream(fileName);
		}
		return stream;
	}
	
	/*
	 * Outputs DOM representation to the standard output stream.
	 *
	 * @param root The DOM representation to be outputted
	 */
	public static void dumpDOMDocument(org.w3c.dom.Node root) throws TransformerException, TransformerConfigurationException {
		// https://docs.oracle.com/cd/E17802_01/webservices/webservices/docs/2.0/xmldsig/api/javax/xml/crypto/doc-files/SignedSoap.java
		System.out.println("DumpDOMDocument: \n");
		// Create a new transformer object
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		// Dump the DOM representation to standard output
		transformer.transform(new DOMSource(root), new StreamResult(System.out));
		System.out.println("\n");
	}
	public static String toStringDocument(Document doc) throws TransformerException {
		StringWriter sw = new StringWriter();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		// If Yes then it removes <?xml version="1.0" encoding="UTF-8"?>
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		// On using "INDENT:yes" i have received "SOAP XML: Incorrect message signing". So use as "INDENT:no"
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

		transformer.transform(new DOMSource(doc), new StreamResult(sw));
		return sw.toString();
	}
	
	// XPath
	// String jsonNameSpaces = "{'soapenv':'http://schemas.xmlsoap.org/soap/envelope/'}";
	/*
<dependency>
  <groupId>org.apache.ws.commons.util</groupId>
  <artifactId>ws-commons-util</artifactId>
  <version>1.0.2</version>
  <exclusions>
	<exclusion>
	  <groupId>xml-apis</groupId>
	  <artifactId>xml-apis</artifactId>
	</exclusion>
  </exclusions>
</dependency>
	 */
	public static javax.xml.xpath.XPath getNameSpaceXpath(String jsonNameSpaces) {
		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();
		
		if (jsonNameSpaces != null) {
		org.json.simple.JSONObject namespaces = getJSONObjectNameSpaces(jsonNameSpaces);
		if ( namespaces.size() > 0 ) {
			// 1.0.2 : https://mvnrepository.com/artifact/org.apache.ws.commons.util/ws-commons-util
			// org.apache.ws.commons.util.NamespaceContextImpl
			org.apache.ws.commons.util.NamespaceContextImpl nsContext = new org.apache.ws.commons.util.NamespaceContextImpl();

			Iterator<?> key = namespaces.keySet().iterator();
			while (key.hasNext()) { // Apache WebServices Common Utilities
				String pPrefix = key.next().toString();
				String pURI = namespaces.get(pPrefix).toString();
				nsContext.startPrefixMapping(pPrefix, pURI);
			}
			xpath.setNamespaceContext(nsContext );
		}
		}
		return xpath;
	}
	static org.json.simple.JSONObject getJSONObjectNameSpaces( String jsonNameSpaces ) {
		// 1.1 : https://mvnrepository.com/artifact/com.googlecode.json-simple/json-simple
		if(jsonNameSpaces.indexOf("'") > -1)	jsonNameSpaces = jsonNameSpaces.replace("'", "\"");
		org.json.simple.parser.JSONParser parser = new org.json.simple.parser.JSONParser();
		org.json.simple.JSONObject namespaces = null;
		try {
			namespaces = (org.json.simple.JSONObject) parser.parse(jsonNameSpaces);
		} catch (org.json.simple.parser.ParseException e) {
			e.printStackTrace();
		}
		return namespaces;
	}
	public static NodeList getNodesFromXpath( Document doc, String xpathExpression, String jsonNameSpaces ) {
		try {
			XPathFactory xpf = XPathFactory.newInstance();
			XPath xpath = xpf.newXPath();

			JSONObject namespaces = getJSONObjectNameSpaces(jsonNameSpaces);
			if ( namespaces.size() > 0 ) {
				// 1.0.2 : https://mvnrepository.com/artifact/org.apache.ws.commons.util/ws-commons-util
				org.apache.ws.commons.util.NamespaceContextImpl nsContext = new org.apache.ws.commons.util.NamespaceContextImpl();

				Iterator<?> key = namespaces.keySet().iterator();
				while (key.hasNext()) { // Apache WebServices Common Utilities
					String pPrefix = key.next().toString();
					String pURI = namespaces.get(pPrefix).toString();
					nsContext.startPrefixMapping(pPrefix, pURI);
				}
				xpath.setNamespaceContext(nsContext );
			}

			XPathExpression compile = xpath.compile(xpathExpression);
			NodeList nodeList = (NodeList) compile.evaluate(doc, XPathConstants.NODESET);
			return nodeList;
			
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return null;
	}
	public static NodeList getNodesList(Node context, String xpath) {
		NodeList result = null;
		try {
			result = XPathAPI.selectNodeList(context, xpath);
		} catch (TransformerException e) {
			throw new Error("TransformerException: " + e.getMessage(), e);
		}
		return result;
	}
}
class TechnicalDeliveryException extends Exception {
	private static final long serialVersionUID = 372683934322930080L;
	public TechnicalDeliveryException() {
		super();
	}
	public TechnicalDeliveryException(String message) {
		super(message);
	}
	public TechnicalDeliveryException(Throwable cause) {
		super(cause);
	}
	public TechnicalDeliveryException(String message, Throwable cause) {
		super(message, cause);
	}
}
class HttpConnectionFactory {
	private static final Log log = LogFactory.getLog(HttpConnectionFactory.class);
	private Proxy proxy;
	private String proxyHost;
	private Integer proxyPort;
	private String clientCertificatePassword;
	private InputStream clientCertificateStream;
	private String ceritificateAlias;
	public HttpConnectionFactory() {
	}
	public HttpConnectionFactory(String proxyHost, Integer proxyPort) {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
	}

	private void initializeProxy() {
		proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
	}
/*
<dependency>
	<groupId>org.glassfish.jersey.core</groupId>
	<artifactId>jersey-client</artifactId>
	<version>2.25.1</version>
</dependency>

<dependency>
	<groupId>org.glassfish.jersey.core</groupId>
	<artifactId>jersey-common</artifactId>
	<version>2.25.1</version>
</dependency>

<dependency>
	<groupId>org.glassfish.jersey.connectors</groupId>
	<artifactId>jersey-apache-connector</artifactId>
	<version>2.25.1</version>
</dependency>
<dependency>
	<groupId>org.glassfish.jersey.inject</groupId>
	<artifactId>jersey-hk2</artifactId>
	<version>2.26</version>
</dependency>
*/
	public javax.ws.rs.core.Configuration getClientConfig() {
		org.glassfish.jersey.client.ClientConfig config = new org.glassfish.jersey.client.ClientConfig();
		config.connectorProvider(new org.glassfish.jersey.apache.connector.ApacheConnectorProvider());
		//Commenting proxy host and port for CLOUD changes - org.glassfish.jersey.client.ClientProperties
		//config.property(ClientProperties.PROXY_URI, "http://" + proxyHost + ":" + proxyPort);
		// config.property(ClientProperties.PROXY_USERNAME, "YASH_777");
		// config.property(ClientProperties.PROXY_PASSWORD, "GitHUb_StackOverflow");
		return config;
	}

	public HttpURLConnection getHttpURLConnection(URL url) throws IOException {
		HttpURLConnection httpURLConnection = null;
		HttpsURLConnection httpsURLConnection = null;
		if (proxyHost != null && proxyPort != null) {
			initializeProxy();
			httpURLConnection = (HttpURLConnection) url.openConnection(proxy);
		} else {
			httpURLConnection = (HttpURLConnection) url.openConnection();
		}

		if (httpURLConnection instanceof HttpsURLConnection) { // sun.net.www.protocol.https.DelegateHttpsURLConnection:
			try {
				httpsURLConnection = getHttpsConnection(url);
			} catch (TechnicalDeliveryException e) {
				log.error(e, e); // com.java.xml.TechnicalDeliveryException: java.security.cert.CertificateParsingException: java.io.IOException: ObjectIdentifier() -- data isn't an object ID (tag = 49)
			}
			return httpsURLConnection;
		} else {
			return httpURLConnection;
		}
	}

	private HttpsURLConnection getHttpsConnection(URL url) throws IOException, TechnicalDeliveryException {
		HttpsURLConnection httpsURLConnection = null;
		try {
			if (proxy != null) {
				log.info("proxy based::" + proxy);
				httpsURLConnection = (HttpsURLConnection) url.openConnection(proxy);
			} else {
				log.info("without proxy::");
				httpsURLConnection = (HttpsURLConnection) url.openConnection();
			}

			httpsURLConnection.setHostnameVerifier(getHostnameVerifier());

			SSLSocketFactory sslSocketFactory = null;
			if (clientCertificatePassword != null) {
				log.info("with password::");
				sslSocketFactory = this.getKeyStoreBasedSSLContext().getSocketFactory();

			} else {
				log.info("without password::");
				sslSocketFactory = this.getCertificateFactoryBasedSSLContext().getSocketFactory();
			}

			if (sslSocketFactory != null) {
				httpsURLConnection.setSSLSocketFactory(sslSocketFactory);
			} else {
				throw new TechnicalDeliveryException("sslSocketFactory for sslcontext is null");
			}
		} catch (KeyManagementException e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		}  catch (KeyStoreException e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		} catch (NoSuchAlgorithmException e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		} catch (CertificateException e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		} catch (UnrecoverableKeyException e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		}
		return httpsURLConnection;
	}

	public HostnameVerifier getHostnameVerifier() {
		return new HostnameVerifier() {
			public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
				return true;
			}
		};
	}

	public SSLContext getCertificateFactoryBasedSSLContext() throws CertificateException, NoSuchAlgorithmException,
			KeyStoreException, IOException, KeyManagementException, TechnicalDeliveryException {
		CertificateFactory certificateFactory;
		X509Certificate x509Certificate;
		TrustManagerFactory trustManagerFactory;
		KeyStore keyStore;
		SSLContext sslContext = null;
		BufferedInputStream bufferedInputStream = null;
		try {
			bufferedInputStream = new BufferedInputStream(clientCertificateStream);
			certificateFactory = CertificateFactory.getInstance("X.509");
			x509Certificate = (X509Certificate) certificateFactory.generateCertificate(bufferedInputStream);
			trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null);

			keyStore.setCertificateEntry(ceritificateAlias, x509Certificate);

			trustManagerFactory.init(keyStore);
			sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
		} catch (Exception e) {
			log.error(e, e);
			throw new TechnicalDeliveryException(e);
		} finally {
			close(bufferedInputStream);
			close(clientCertificateStream);
		}
		return sslContext;
	}

	public SSLContext getKeyStoreBasedSSLContext() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException, KeyManagementException, TechnicalDeliveryException
	{
		SSLContext sslContext = null;
		KeyStore clientStore = KeyStore.getInstance("PKCS12");
		BufferedInputStream bufferedInputStream = new BufferedInputStream(clientCertificateStream);
		try {
			log.info("loading certificate into client store");
			clientStore.load(bufferedInputStream, clientCertificatePassword.toCharArray());

			KeyManagerFactory keyManagerFactory = KeyManagerFactory
					.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(clientStore, clientCertificatePassword.toCharArray());
			KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

			sslContext = SSLContext.getInstance("SSL");
			sslContext.init(keyManagers, null, new SecureRandom());
			log.info("initialized sslcontext");
		} catch (Exception e) {
			log.error(e, e);

			throw new TechnicalDeliveryException(e);
		} finally {
			close(bufferedInputStream);
			close(clientCertificateStream);
		}
		return sslContext;
	}
	public static void close(Closeable resource) {
		if (resource != null) {
			try {
				resource.close();
			} catch (IOException e) {
				log.error(e,e);
			}
		}
	}
	public void setClientCertificatePassword(String clientCertificatePassword) {
		this.clientCertificatePassword = clientCertificatePassword;
	}
	public void setClientCertificateStream(InputStream clientCertificateStream) {
		this.clientCertificateStream = clientCertificateStream;
	}
	public void setCeritificateAlias(String ceritificateAlias) {
		this.ceritificateAlias = ceritificateAlias;
	}
}
