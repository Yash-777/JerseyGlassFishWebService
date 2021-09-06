package com.github.yash777.mail;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.stream.Stream;
import java.util.zip.ZipInputStream;

import javax.activation.CommandInfo;
import javax.activation.DataHandler;
import javax.mail.Address;
import javax.mail.BodyPart;
import javax.mail.Flags;
import javax.mail.Folder;
import javax.mail.Header;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.Flags.Flag;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import org.apache.commons.io.IOUtils;
import org.apache.poi.hsmf.MAPIMessage;
import org.apache.poi.hsmf.exceptions.ChunkNotFoundException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import ch.astorm.jotlmsg.OutlookMessage;
import ch.astorm.jotlmsg.OutlookMessageAttachment;
import ch.astorm.jotlmsg.OutlookMessageRecipient;
import net.markenwerk.utils.mail.smime.SmimeKey;
import net.markenwerk.utils.mail.smime.SmimeState;
import net.markenwerk.utils.mail.smime.SmimeUtil;

/*<dependency>
<groupId>ch.astorm</groupId> <artifactId>jotlmsg</artifactId> <version>1.7</version>
</dependency>*/

// Exception in thread "main" org.apache.poi.poifs.filesystem.NotOLE2FileException: Invalid header signature; read 0x2D746E65746E6F43, expected 0xE11AB1A1E011CFD0 - Your file appears not to be a valid OLE2 document

public class IMAP_MimeMail {
	//String server, String username, String password, int port, String protocol, int readMailsCont
		String server, username, password, protocol;
		int port, readMailsCont;
		static String mailBoxFolder = "Inbox"; //"Mail Test"; // Inbox
		
	boolean isStoreMessage;
	public IMAP_MimeMail (/*boolean isSigned, boolean isEncrypted, */boolean isStoreMessage) {
		/*this.isSigned = isSigned;
		this.isEncrypted = isEncrypted;*/
		this.isStoreMessage = isStoreMessage;
	}
	
	// setMailProperties("outlook.office365.com", "user@gmail.com", "supportGroup@gmail.com", 993, "imap", 2, "Mail Test")
	public void setMailProperties(String server, String username, String password, int port,
			String protocol, int readMailsCont, String mailBoxFolder) {
		this.server = server;
		this.username = username;
		this.password = password;
		this.port = port;
		this.protocol = protocol;
		this.readMailsCont = readMailsCont;
		this.mailBoxFolder = mailBoxFolder;
	}
	
	
	static boolean readMailDetails= false, msgDeleteOnRead = false;
	
	static String security_privatekey = 
			"power-ops.pfx", passwordCert="123";
			//"Baeldung.p12", passwordCert ="password";
	static String security_certificate = 
			"power-ops-base.cer";
			//"Baeldung.cer";
	static String filePath ="C:/Yash/JMail/";
	static String emlReadFile = "C:/Yash/JMail/MAIL_2021-03-19T15-13-03Z_xml _sign_ _encrypt_.eml";
			//SendingMessage_20210212_092519.eml";  // .msg, .eml
	
	static FileOpreations fileObj = new FileOpreations();
	
	private static DateFormat df = null;
	private static final String DATEPATTERN_STR = "dd.MM.yyyy HH:mm:ss";
	static {
		df = new SimpleDateFormat(DATEPATTERN_STR);
		TimeZone cetTime = TimeZone.getTimeZone("CET");
		df.setTimeZone(cetTime);
		
		Security.addProvider(new BouncyCastleProvider());
	}
	private static String formatDate(java.util.Date d) {
		if (d == null)
			return "";
		return df.format(d);
	}
	
	public static void main(String[] args) throws MessagingException, IOException /*,ChunkNotFoundException*/ {
		//mailFetch("outlook.office365.com", "user@gmail.com", "supportGroup@gmail.com", 993, "imap", 2);
		// String server, String username, String password, int port, String protocol, int readMailsCont
		
		//IMAP_MimeMail obj = new IMAP_MimeMail(/*true, true,*/ true);
		IMAP_MimeMail obj = new IMAP_MimeMail(/*true, true,*/ false);
		int readMailBoxMailsCount = 5;
		obj.setMailProperties("outlook.office365.com", "user@gmail.com", "Password2017", 993, "imap", readMailBoxMailsCount, "Mail Test");
		obj.mailRead();
		
	}
	
	// MessageDigest md = MessageDigest.getInstance("SHA-256"); //MD5, SHA, MD2, MD5, SHA-256, SHA-384...
	// MessageDigest md = MessageDigest.getInstance("MD5");
	public static String ContentIntegrityCheck(InputStream is, MessageDigest md) throws IOException, NoSuchAlgorithmException {
		// file hashing with DigestInputStream
		try (DigestInputStream dis = new DigestInputStream(is, md)) {
			while (dis.read() != -1) ; //empty loop to clear the data
			md = dis.getMessageDigest();
		}
		// bytes to hex
		StringBuilder result = new StringBuilder();
		for (byte b : md.digest()) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}
	private static Properties getIMAPProperties(String protocol, int port) {
		Properties props = new Properties();
		props = System.getProperties();
		if (protocol.equalsIgnoreCase("IMAP") || protocol.equalsIgnoreCase("IMAPS"))
		{
			props.setProperty("mail.imap.partialfetch", "false");
			
			if (protocol.equalsIgnoreCase("IMAPS")) {
				props.setProperty("mail.imap.ssl.enable", "true");
			} else {
				props.setProperty("mail.imap.ssl.enable", "false");
			}
			
			/*props.setProperty("mail.debug.auth ", "true");
			//props.setProperty("mail.imaps.starttls.enable", "true");
			props.setProperty("mail.imaps.auth", "true");*/
			// set this session up to use SSL for IMAP connections
			props.setProperty("mail.imap.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
			// don't fallback to normal IMAP connections on failure.
			props.setProperty("mail.imap.socketFactory.fallback", "false");
			// use the simap port for imap/ssl connections.
			props.setProperty("mail.imap.socketFactory.port", port + "");

			
			props.setProperty("mail.imap.auth.plain.disable", "true");
			//props.setProperty("mail.imaps.auth.plain.disable", "true");

			/*props.setProperty("mail.debug", "true");
			props.setProperty("mail.imaps.auth.ntlm.disable", "true");*/
			// props.setProperty("mail.imap.auth.plain.disable", "true");
			// -Dmail.imaps.auth.plain.disable=true
			
			/*DEBUG IMAPS: mechanism PLAIN disabled by property: mail.imaps.auth.plain.disable
			DEBUG IMAPS: mechanism LOGIN not supported by server
			DEBUG IMAPS: mechanism NTLM disabled by property: mail.imaps.auth.ntlm.disable
			DEBUG IMAPS: mechanism XOAUTH2 disabled by property: mail.imaps.auth.xoauth2.disable*/
		}
		return props;
	}
	
	public void mailRead() throws IOException, MessagingException {
		if (isStoreMessage) {
			File emlFile = new File(emlReadFile);
			InputStream source = new FileInputStream(emlFile);
			
			/*// .EML
			Properties props = System.getProperties();
			mailSession = Session.getDefaultInstance(props, null);
			MimeMessage message = new MimeMessage(mailSession, source);

			InputStream mapiMessageInputStream = source;
			MAPIMessage mapiMessage = new MAPIMessage(mapiMessageInputStream);
			mailSession = Session.getInstance(new Properties());
			//OutlookMSG.toMimeMessage(mailSession, mapiMessage);
			
			// .MSG
			OutlookMessage message0 = new OutlookMessage(source);
			message = message0.toMimeMessage(); // javax.mail.MessagingException: missing body
			//message.writeTo(new FileOutputStream(new File("C:/Yash/Mail/MSG_TestMail_myMessage.eml")));
			
			// When USE .eml file as Outlook
			// org.apache.poi.poifs.filesystem.NotOLE2FileException: Invalid header signature; read 0x4D22203A6D6F7246, expected 0xE11AB1A1E011CFD0 - Your file appears not to be a valid OLE2 document
			*/
			try {
				Properties props = System.getProperties();
				//props.put("mail.host", "smtp.dummydomain.com");
				// props.put("mail.transport.protocol", "smtp");
				Session mailSession = Session.getDefaultInstance(props, null);
				MimeMessage message = new MimeMessage(mailSession, source);
				
				System.out.println("MSG: "+ message);
				
				String contentMD5 = message.getContentMD5();
				System.out.println("Content MD5"+ contentMD5);
				
				String contentID = message.getContentID();
				System.out.println("contentID :"+contentID);
			
				Enumeration enumer = message.getAllHeaders();
				
				System.out.println("===== Headers Start");
				while (enumer.hasMoreElements()) {
					Header header = (Header) enumer.nextElement();
					System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
				}
				System.out.println("===== Headers End");
				
				// https://stackoverflow.com/questions/7776069/confirming-file-content-against-hash
				// https://mkyong.com/java/how-to-generate-a-file-checksum-value-in-java/
			/* // MessageDigest md = MessageDigest.getInstance("SHA-256"); //SHA, MD2, MD5, SHA-256, SHA-384...
				// MessageDigest md = MessageDigest.getInstance("MD5");
				public static String ContentIntegrityCheck(InputStream is, MessageDigest md)*/
				
				String contentIntegrityCheck = ContentIntegrityCheck(message.getRawInputStream(), MessageDigest.getInstance("MD5"));
				System.out.println("contentIntegrityCheck :"+ contentIntegrityCheck);
				
				String contentIntegrityCheck2 = ContentIntegrityCheck(message.getRawInputStream(), MessageDigest.getInstance("SHA-256"));
				System.out.println("contentIntegrityCheck :"+ contentIntegrityCheck2);
				
				String contentIntegrityCheck3 = ContentIntegrityCheck(message.getInputStream(), MessageDigest.getInstance("MD5"));
				System.out.println("contentIntegrityCheck :"+ contentIntegrityCheck3);
				
				String contentIntegrityCheck4 = ContentIntegrityCheck(message.getInputStream(), MessageDigest.getInstance("SHA-256"));
				System.out.println("contentIntegrityCheck :"+ contentIntegrityCheck4);
				
				/*if (contentMD5.equals(contentIntegrityCheck)) {
					System.out.println("contentIntegrityCheck : success");
				}*/
				
				if (readMailDetails) {
					AckMailData readMailDetails = readMailDetails(message);
					System.out.println("readMailDetails:"+readMailDetails);
					//AckMailData readMailDetails = readMimeContent(message);
				}

			}  catch (Exception e)  {
				e.printStackTrace();
			}
		
		} else {
			
			mailFetch(server, username, password, port, protocol, readMailsCont);
		}
	}
	static Session mailSession;

	protected static String localMsgString = "";
	private List mailFetch(String server, String username, String password, int port, String protocol, int readMailsCont)
	{
		List messagedata = new ArrayList();
		Store store = null;
		Folder inboxFolder = null;// , archiveFolder = null;

		try
		{
			Message[] messages = null;
			
				try {
					Properties imapProps = getIMAPProperties(protocol, port);
					Session session = Session.getInstance(imapProps, null);
					session.setDebug(true);
					store = session.getStore(protocol.toLowerCase());
					localMsgString+="\nConnecting Store with --Server:" + server + " port:" + port + " username:" + username; 
					System.out.println("Connecting Store with --Server:" + server + " port:" + port + " username:" + username); 
					
					mailSession  = session;
					store.connect(server, username, password);
					if (store.isConnected()) {
						System.out.println("*******************imap store connected*****************");
					}
					
					localMsgString+="\nConnect Succeed";
					
					inboxFolder = store.getFolder( mailBoxFolder );
					//inboxFolder.setFlags(messages, new Flags(Flags.Flag.SEEN), true); // NullPointerException: Cannot read the array length because "messages" is null
					inboxFolder.open(Folder.READ_WRITE);
					messages = inboxFolder.getMessages();
					
					// If using below lines then Open folder in Folder.READ_WRITE mode.
					//inboxFolder.setFlags(messages, new Flags(Flags.Flag.SEEN), true); // True:  Marks all Folder messages as Read.
					//inboxFolder.setFlags(messages, new Flags(Flags.Flag.SEEN), false);  // False: Marks all Folder messages as Un-Read
					
				}  catch (Exception e)  {
					e.printStackTrace();
				}
			
			int messagesLength = messages.length;
			
			localMsgString+="\nMessage Count in Folder "+mailBoxFolder+":" + messagesLength;
			System.out.println("Message Count in Folder "+mailBoxFolder+":" + messagesLength);
			
			if (readMailsCont == 0) {
				readMailsCont = 2;
			}
			
			for (int i = 0; i < messagesLength && i < readMailsCont; i++)
			{
				
				MimeMessage message = (MimeMessage) messages[i];
				
				Enumeration enumer = message.getAllHeaders();
				
				System.out.println("===== Headers Start");
				while (enumer.hasMoreElements()) {
					Header header = (Header) enumer.nextElement();
					System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
				}
				System.out.println("===== Headers End");
				
				// FLAGS (\Seen \Answered \Flagged \Deleted \Draft $MDNSent)
				Flags flags = message.getFlags();
				System.out.println("====== flags :"+flags);
				// FLAGS ()        - unread mail, but java program collected this message obj, but its status is unread.
				// FLAGS (\Recent) - Java program not read this mail till now. Recently arrived mail. Status Unread.
				// FLAGS (\Seen)   - Seen Message
				// FLAGS (\Flagged)- User Flagged this mail for urgent/special attention
				boolean mailFlag = message.isSet(Flags.Flag.SEEN); // Check whether the flag specified in the flag argument is set in this message
				System.out.println("Flags.Flag.SEEN:"+mailFlag);
				
				// https://serverfault.com/questions/115769/which-imap-flags-are-reliably-supported-across-most-mail-servers
				// https://stackoverflow.com/questions/6898178/is-it-possible-to-find-if-message-is-unread-using-java-mail-api
				if (mailFlag) {
					System.out.println("FLAGS (\\Seen) - Read Mail :("+flags+")");
				} else {
					System.out.println("FLAGS () - UnRead Mail :("+flags+")");
				}
				
				
				if (readMailDetails) {
					AckMailData readMailDetails = readMailDetails(message);
					
					messagedata.add(readMailDetails);
					
					if(msgDeleteOnRead) {
						messages[i].setFlag(Flag.DELETED, true);
					}
				}

			}
			// returnMsgString = ":scanned InBOX > msg cnt :" + messages.length;
		}
		catch (Throwable e)
		{
			e.printStackTrace();
			localMsgString += "\n[mailFetch()#3:" + getExceptionAsString(e);
		}
		finally
		{
			if (inboxFolder != null)
			{
				try
				{
					inboxFolder.close(true);
				}
				catch (MessagingException e)
				{
					e.printStackTrace();
				}
			}

			if (store != null)
			{
				try
				{
					store.close();
				}
				catch (MessagingException e)
				{
					e.printStackTrace();
				}
			}
		}
		return messagedata;
	}
	
	public static AckMailData readMailDetails(MimeMessage message) throws MessagingException, IOException {
		AckMailData data = new AckMailData();
		
		System.out.println("===== ----- Message ----- =====");
		System.out.println("MimeMessage : "+ message +" <<< END");
		
			Enumeration enumer = message.getAllHeaders();
			
			System.out.println("===== Headers Start : readMailDetails");
			while (enumer.hasMoreElements()) {
				Header header = (Header) enumer.nextElement();
				System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
			}
			System.out.println("===== Headers End : readMailDetails");
			
		// Choosing character set of the mail message
		// First: looking it from MimeType
		String mimeType = message.getHeader("Content-type", ";");
		String charset;
		int pos;
		if (mimeType == null || (pos = mimeType.indexOf("charset")) < 0)
		{
			// Using default
			charset = "ISO-8859-1";
		}
		else
		{
			// Assuming mime type in form
			// "text/XXXX; charset=XXXXXX"
			StringTokenizer token = new StringTokenizer(mimeType.substring(pos), "=; ");
			token.nextToken();
			charset = token.nextToken();
		}
		localMsgString += "\n[charset:" + charset + "]";
		
		// From Address
		Address[] fromEmailAddress = message.getFrom();
		String fromString = getAddress(fromEmailAddress);
		data.setFrom(fromString);
		/*if (fromString != null && fromString != "__EMPTY__") { // getAddress
			data.setFrom(fromString.length() > 255 ? fromString.substring(0, 255) : fromString);
		}*/
						
		// To Address
		Address[] toEmailAddress = message.getAllRecipients();
		String toString = getAddress(toEmailAddress);
		data.setTo(toString);
		
		data.setSubject(message.getSubject());
		data.setMailDate(formatDate(message.getSentDate()));
		
		Object content = message.getContent();
		
		if (content instanceof MimeMultipart)
		{
			System.out.println("----- MimeMultipart Content");
			
			MimeMultipart multipart = (MimeMultipart) message.getContent();
			int countParts = multipart.getCount();
			for (int j = 0; j < countParts; j++)
			{
				BodyPart bp = multipart.getBodyPart(j);
				if (bp.getFileName() != null && bp.getFileName().length() > 0)
				{
					data.setAttachmentName(bp.getFileName());
					data.setAttachmentDataStream(bp.getInputStream());
					/*InputStreamReader reader = new InputStreamReader(bp.getInputStream());
					data.setAttachmentData(reader);*/
				}
				else
				{
					BufferedReader reader = new BufferedReader(new InputStreamReader(bp.getInputStream(), charset));
					StringBuffer sb = new StringBuffer();
					while (reader.ready())
					{
						sb.append(reader.readLine());
						sb.append(System.getProperty("line.separator"));
					}
					String bodyString = sb.toString();
					data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
					data.setFpId(null);
					data.setHttpDetail(null);
				}
			}
		}
		else if (content instanceof String)
		{
			System.out.println("===== String Content");
			String bodyString = (String) content;
			data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
			data.setAttachmentName(null);
			//data.setAttachmentData(null);
			data.setFpId(null);
			data.setHttpDetail(null);
		} else {
			System.out.println("===== special message");
			
			try {
				data = fetchEnvelopedContent(message, data, charset);
			} catch (Exception e) {
				System.out.println("Special MSG Exception:"+e.getMessage());
				
				e.printStackTrace();
			}
			
		}
		return data;
	}
	private static String  getExceptionAsString(Throwable e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString();
	}

	
/*	private static AckMailData readMimeContent(MimeMessage message) {
		AckMailData data = new AckMailData();
		try {
			
			System.out.println("MSG: "+ message);
			
			Address[] fromEmailAddress = message.getFrom();
			String fromString = getAddress(fromEmailAddress);
			data.setFrom(fromString);
			Address[] toEmailAddress = message.getAllRecipients();
			String toString = getAddress(toEmailAddress);
			data.setTo(toString);
			data.setSubject(message.getSubject());
			
			String mimeType = message.getHeader("Content-type", ";");
			System.out.println("mimeType :"+mimeType);
			String charset = getCharset(mimeType);
			
			// Content-Type ~:~ application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data
			if (mimeType != null && mimeType.contains("smime-type=enveloped-data")) { // S/MIME Encrypted
				System.out.println("S/MIME Encrypted Mail");
				
				MimeBodyPart decryptedPart = getDecryptedPart(message);
				mimeType = decryptedPart.getHeader("Content-type", ";");
				System.out.println("mimeType :"+mimeType);
				
				if (mimeType.contains("multipart/signed;")) { // S/MIME Signed
					System.out.println("S/MIME Signed Encrypted Mail");
					
					// Content-Type ~:~ multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-1;
					MimeBodyPart signedMimeMessage = decryptedPart;
					getSignedParts(signedMimeMessage, charset, data);
					
				}
			// Content-Type ~:~ application/pkcs7-mime; name=smime.p7m; smime-type=signed-data
			} else if (mimeType != null && mimeType.contains("smime-type=signed-data")) { // S/MIME Signed
				System.out.println("S/MIME Signed Mail");
				
				MimeMessage signedMimeMessage = message;
				
				SMIMESignedParser signedParser = null; // https://stackoverflow.com/a/57722857/5081877
				DigestCalculatorProvider build = new JcaDigestCalculatorProviderBuilder().build();
				if (signedMimeMessage.isMimeType("multipart/signed")) {
					System.out.println("signedMimeMessage : multipart/signed");
					signedParser = new SMIMESignedParser(build, signedMimeMessage);
				} else if (signedMimeMessage.isMimeType("application/pkcs7-mime")) {
					System.out.println("signedMimeMessage : application/pkcs7-mime");
					signedParser = new SMIMESignedParser(build, signedMimeMessage);
				} else {
					throw new IllegalArgumentException("This mimeMessage is not signed.");
				}
				
				X509Certificate x509Cert = CertsUtil.getX509Cert(security_certificate);
				boolean verifySigniture = verifySigniture(signedParser, x509Cert);
				//boolean verifySigniture = verifySigniture(signedParser, null); // https://stackoverflow.com/a/57722857/5081877
				System.out.println("verifySigniture: "+verifySigniture);
				
				MimeBodyPart signedMimeMessageBody = signedParser.getContent();
				
				// multipart/mixed;  boundary="----=_Part_0_1131040331.1597575334188"
				
				MimeMultipart simpleMail = (MimeMultipart) signedMimeMessageBody.getContent();
				int partsCount = simpleMail.getCount();
				System.out.println("----- MimeMultipart Content, Count:"+partsCount); // 2
				
				// BodyPart, AttachementPart
				for (int k = 0; k < partsCount; k++) {
					MimeBodyPart bodyPart = (MimeBodyPart) simpleMail.getBodyPart(k);
					String contentType = bodyPart.getContentType();
					System.out.println("getContentType: "+contentType);
					
					getMultiPart(bodyPart, charset, data);
				}
				
			} else { // S/MIME
				System.out.println("S/MIME Mail :" + message);
				
				getHeaders(message);
				
				Object content = message.getContent();
				System.out.println("::"+content);
				if (content instanceof MimeMultipart) {
					System.out.println("----- MimeMultipart Content");
					
					MimeMultipart multipart = (MimeMultipart) message.getContent();
					int countParts = multipart.getCount();
					for (int j = 0; j < countParts; j++) {
						
						MimeBodyPart bodyPart = (MimeBodyPart) multipart.getBodyPart(j);
						String contentType = bodyPart.getHeader("Content-type", ";");
						System.out.println("Content-type :"+contentType);
						
						String contentDes = bodyPart.getHeader("Content-Disposition", ";");
						System.out.println("Content-Disposition :"+contentDes);
						
						//getHeaders(bodyPart);
						
						if ( (contentType != null && contentType.contains("multipart/")) || (contentDes != null && contentDes.contains("attachment")) ) {
							System.out.println("===== MimeMultipart Content");
							getMultiPart(bodyPart, charset, data);
						}
					}
				} else if (content instanceof String) {
					System.out.println("===== String Content");
					String bodyString = (String) content;
					data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
				} else {
					
				}
			}
			
			System.out.println("Data:"+data);
		}  catch (Exception e)  {
			e.printStackTrace();
		}
		return data;
	}
	public static String getCharset(String mimeType) {
		String charset = "";
		int pos;
		if (mimeType == null || (pos = mimeType.indexOf("charset")) < 0) {
			charset = "ISO-8859-1"; // Using default
		} else if (mimeType != null) {
			StringTokenizer token = new StringTokenizer(mimeType.substring(pos), "=; ");
			token.nextToken();
			charset = token.nextToken();
		}
		return charset;
	}
	public static void getHeaders(Part bodyPart) throws IOException, MessagingException {
		Enumeration<?> enumer = bodyPart.getAllHeaders();
		System.out.println("===== Headers Start");
		while (enumer.hasMoreElements()) {
			Header header = (Header) enumer.nextElement();
			System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
		}
		System.out.println("===== Headers End");
	}
	private static void getSignedParts(MimeBodyPart signedMessage, String charset, AckMailData data) throws Exception {
		
		String mimeType = signedMessage.getHeader("Content-type", ";");
		System.out.println("signedMessage mimeType :"+mimeType);
		
		SMIMESignedParser signedParser = null; // https://stackoverflow.com/a/57722857/5081877
		DigestCalculatorProvider build = new JcaDigestCalculatorProviderBuilder().build();
		if (mimeType.contains("multipart/signed")) { // multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-1;
			System.out.println("signedMimeMessage : multipart/signed");
			signedParser = new SMIMESignedParser(build, (MimeMultipart) signedMessage.getContent());
		} else if (mimeType.contains("application/pkcs7-mime")) {
			System.out.println("signedMimeMessage : application/pkcs7-mime");
			signedParser = new SMIMESignedParser(build, (MimeMultipart) signedMessage.getContent());
		} else {
			throw new IllegalArgumentException("This mimeMessage is not signed.");
		}
		boolean verifySigniture = verifySigniture(signedParser, null);
		System.out.println("verifySigniture: "+verifySigniture);
		
		// === -- ===
		Object content = signedMessage.getContent();
		if (content instanceof MimeMultipart) {
			MimeMultipart multipart = (MimeMultipart) signedMessage.getContent();
			int countParts = multipart.getCount();
			System.out.println("----- Signed MimeMultipart Content, Count:"+countParts);
			
			// SignedPart, MailPart
			for (int j = 0; j < countParts; j++) {
				MimeBodyPart signedBodyPart = (MimeBodyPart) multipart.getBodyPart(j);
				
				Object signedContent = signedBodyPart.getContent();
				if (signedContent instanceof MimeMultipart) {
					
					MimeMultipart simpleMail = (MimeMultipart) signedBodyPart.getContent();
					int partsCount = simpleMail.getCount();
					System.out.println("----- MimeMultipart Content, Count:"+partsCount); // 2
					
					// BodyPart, AttachementPart
					for (int k = 0; k < partsCount; k++) {
						MimeBodyPart bodyPart = (MimeBodyPart) simpleMail.getBodyPart(k);
						String contentType = bodyPart.getContentType();
						System.out.println("getContentType: "+contentType);
						
						getMultiPart(bodyPart, charset, data);
					}
				}
			}
		}
	}
	public static void getMultiPart(MimeBodyPart bodyPart, String charset, AckMailData data) throws Exception {
		String contentDes = bodyPart.getHeader("Content-Disposition", ";");
		System.out.println("Content-Disposition :"+contentDes);
		boolean continueFilePart = true;
		if ( (contentDes != null && contentDes.contains("attachment" )) && (bodyPart.getFileName() != null && bodyPart.getFileName().equals("body")) ) {
			System.out.println("... Convert Outlook message to MIME message (convert .msg to .eml)");
			continueFilePart = false;
		}
		if (bodyPart.getFileName() != null && bodyPart.getFileName().length() > 0 && continueFilePart) {
			data.setAttachmentName(bodyPart.getFileName());
			InputStreamReader reader = new InputStreamReader(bodyPart.getInputStream());
			//data.setAttachmentData(reader);
		} else {
			BufferedReader reader = new BufferedReader(new InputStreamReader(bodyPart.getInputStream(), charset));
			StringBuffer sb = new StringBuffer();
			if (reader.ready()) {
				String line;
				while ( (line = reader.readLine()) != null) {
					sb.append(line);
					sb.append(System.getProperty("line.separator"));
				}
			}
			String bodyString = sb.toString();
			data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
		}
	}
	
	public static boolean verifySigniture(SMIMESignedParser signedParser, X509Certificate x509Cert) throws CertificateException, CMSException  {
		org.bouncycastle.util.Store<?> certificates = signedParser.getCertificates();
		SignerInformationStore signerInfos = signedParser.getSignerInfos();
		Collection<SignerInformation> signers = signerInfos.getSigners();
		Iterator<SignerInformation> it = signers.iterator();
		while (it.hasNext()) {
			SignerInformation signer = it.next();
			SignerId sid = signer.getSID();
			Collection<?> certCollection = certificates.getMatches(sid);
			Iterator<?> certIt = certCollection.iterator();
			X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
			X509Certificate cert;
			if (x509Cert == null) {
				cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
			} else {
				cert = x509Cert;
				
				byte[] encoded = cert.getEncoded();
				byte[] encoded2 = x509Cert.getEncoded();
				boolean equals = Arrays.equals(encoded, encoded2);
				if (equals) {
					System.out.println("Both Certificates are same.");
				}
			}
			
			try {
				return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
			} catch (Exception e) {
				System.err.println("Error occured during verification"+ e);
			}
		}
		return false;
	}
	*/
	public static MimeBodyPart getDecryptedPart(MimeMessage message) throws Exception {
		MimeBodyPart bodyPartEncrypted = null;
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		InputStream fis = fileObj.getCerFileStream(true, security_privatekey);
		ks.load(fis, passwordCert.toCharArray());
		String alias = ks.aliases().nextElement();

		PrivateKey recipientPrivateKey = (PrivateKey) ks.getKey(alias, passwordCert.toCharArray());
		
		SMIMEEnveloped enveloped = new SMIMEEnveloped((MimeMessage) message);
		RecipientInformationStore recipientsStore = enveloped.getRecipientInfos();
		JceKeyTransRecipient recipientKey = new JceKeyTransEnvelopedRecipient(recipientPrivateKey)
				.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		
		byte[] decryptedData = null;
		InputStream ris = null;
	 // Enveloped Data : https://github.com/bcgit/bc-java/issues/341#issuecomment-635841495
		Collection<RecipientInformation> recipients = recipientsStore.getRecipients();
		Iterator<RecipientInformation> iterator = recipients.iterator();
		while (iterator.hasNext()) {
			RecipientInformation recipientInfo = iterator.next();
			RecipientId rid = recipientInfo.getRID();
			System.out.println("RID: "+rid);
				CMSTypedStream contentStream = recipientInfo.getContentStream(recipientKey);
				ris = contentStream.getContentStream();
				decryptedData = recipientInfo.getContent(recipientKey);
			
			if (decryptedData != null || ris != null)
				break;
		}
		
		if (decryptedData != null) {
			bodyPartEncrypted = SMIMEUtil.toMimeBodyPart(decryptedData);
		} else if (ris != null) {
			bodyPartEncrypted  = SMIMEUtil.toMimeBodyPart(ris);
		}
		return bodyPartEncrypted;
	}

	public static String getAddress(Address[] fromEmailAddress) {
		String fromString = null;
		
		try {
			if(fromEmailAddress != null && fromEmailAddress.length > 0) {
				fromString = "";
				for (int i = 0; i < fromEmailAddress.length; i++) {
					fromString += fromEmailAddress[0].toString();
					
					if (i + 1 < fromEmailAddress.length) {
						fromString += "; ";
					}
				}
			} else {
				fromString = "__EMPTY__";
			}
		} catch (Exception e) {
			e.printStackTrace();
			fromString = "__EMPTY__";
		}
		
		
		return fromString;
	}
	
	
	public static AckMailData fetchEnvelopedContent(MimeMessage message, AckMailData data, String charset) 
			throws CMSException, KeyStoreException, MessagingException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException, SMIMEException, OperatorCreationException, Exception {

		DataHandler dataHandler = message.getDataHandler(); // javax.mail.internet.MimeBodyPart$MimePartDataHandler@159f197
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		 dataHandler.writeTo(baos);
		 baos.flush();
		 System.out.println("DataHndler: "+baos.toString());
		
		try {
		CommandInfo[] allCommands = dataHandler.getPreferredCommands();
		for (int i = 0; i < allCommands.length; i++) {
			CommandInfo commands = allCommands[i];
			System.out.println("commands:"+commands);
			String commandName = commands.getCommandName();
			System.out.println("commandName:"+commandName);
		}
		} catch (Exception e ) { // org.eclipse.debug.core.DebugException: com.sun.jdi.ClassNotLoadedException: Type has not been loaded occurred while retrieving component type of array.
			e.printStackTrace();
		}
		
		String ContentType = "";
		Enumeration enumer = message.getAllHeaders();
		while (enumer.hasMoreElements()) { // ContentType : application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data, Content-Transfer-Encoding ~:~ base64
			Header header = (Header) enumer.nextElement();
			System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
			
			if (header.getName().equalsIgnoreCase("Content-Type")) {
				ContentType = header.getValue();
				System.out.println("ContentType : "+ContentType);
			}
		}
		
		if ( ContentType.contains("enveloped-data") ) {
			System.out.println("====== enveloped-data");
			
			Security.addProvider(new BouncyCastleProvider());
			KeyStore ks = KeyStore.getInstance("PKCS12");

			InputStream fis = fileObj.getCerFileStream(true, security_privatekey);
			//FileInputStream fis = new FileInputStream("c:\\key.pfx");
			//String password = "pfxPassword";
			
			if (null == fis) {
				throw new FileNotFoundException("Certifate File not found.");
			}
			ks.load(fis, passwordCert.toCharArray());
			Enumeration<String> aliases = ks.aliases();
			String alias = null;
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement(); // Alias: Baeldung
				System.out.println("Certificate Alias: "+ alias);
			}
			
			
			// decryptionKey
			PrivateKey recipientPrivateKey = (PrivateKey) ks.getKey(alias, passwordCert.toCharArray());
			X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
			
			SMIMEEnveloped enveloped = new SMIMEEnveloped((MimeMessage) message);
			RecipientInformationStore recipientsStore = enveloped.getRecipientInfos();
			
			String providerName = ks.getProvider().getName();
			System.out.println("KeyStore Provider name:"+providerName);
			System.out.println("KeyStore Type:"+ks.getType());
			
			boolean newWay = false;
			if (newWay) {
				Object content = message.getContent();
				
				if(content instanceof String) {
				     System.out.println("Body: " + content);
				   } else if(content instanceof MimeMultipart) {
					   System.out.println("Multipart");
					   MimeMultipart multi = (MimeMultipart)content;
					     System.out.println("We have a "+ multi.getContentType());              
					     for(int i = 0; i < multi.getCount(); ++i) {
					        BodyPart bo = multi.getBodyPart(i);
					        System.out.println("Content "+i+" is a " + bo.getContentType());
					        //Now that body part could again be a MimeMultipart...
					        Object bodyContent = bo.getContent();
					        //possibly build a recurion here -> the logic is the same as for mm.getContent() above
					      }
				   } else {// com.sun.mail.util.BASE64DecoderStream
				        System.out.println("Some other content: " + content.getClass().getName());
				    }
				
				SmimeState smimeState = net.markenwerk.utils.mail.smime.SmimeUtil.getStatus(message);
				System.out.println("smimeState:"+smimeState);
				
				SmimeKey mimeKey = new SmimeKey(recipientPrivateKey, cert);
				MimeMessage decryptedMessage = SmimeUtil.decrypt(mailSession, message, mimeKey);
				System.out.println("decryptedMessage:"+decryptedMessage);
				
				//MimeBodyPart encryptedBodyPart = message;
				/*SMIMEEnveloped m = new SMIMEEnveloped(message);
				   JceKeyTransRecipientId recId = new JceKeyTransRecipientId(cert);
				   RecipientInformationStore recipients = m.getRecipientInfos();
				   RecipientInformation recipient = recipients.get(recId);
				   JceKeyTransRecipient pKeyRecp = new JceKeyTransEnvelopedRecipient(recipientPrivateKey);
				   MimeBodyPart decrypted = SMIMEUtil.toMimeBodyPart(recipient.getContent(pKeyRecp));
				System.out.println("decrypted MSG:"+decrypted);*/
				
				InputStream envelopedStream = message.getInputStream();
				// use the CMS parser to decrypt the EnvelopedData
				  CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(envelopedStream);
				  // TODO validate the receiving enveloped-data against supported algorithms
				  // look for our recipient identifier
				  /*RecipientId recId = new RecipientId();
				  recId.setSerialNumber(cert.getSerialNumber());
				  recId.setIssuer(cert.getIssuerX500Principal().getEncoded());
				  */
				  
				  
				//KeyTransRecipientId recId2 = new JceKeyTransRecipientId(cert.getIssuerX500Principal(), cert.getSerialNumber());
				//RecipientInformation recipient2 = recipientsStore.get(recId);
				JceKeyTransRecipientId recId3 = new JceKeyTransRecipientId(cert);
				System.out.println("recId3: "+recId3);
				RecipientInformationStore recipients3 = parser.getRecipientInfos();
				System.out.println("recipients3: "+recipients3);
				RecipientInformation recipient3 = recipients3.get(recId3);
				System.out.println("recipient3: "+recipient3);
				
				  /*if (recipient3 != null) {
				    // decrypt the data
				    InputStream unenveloped = recipient3.getContentStream(recipientPrivateKey, "BC").getContentStream();
				    //IoUtil.copyStream(unenveloped, outStream);
				  }*/
				
				/*org.bouncycastle.cms.RecipientId recId = new RecipientId();
				recId.setSerialNumber(cert.getSerialNumber());
				recId.setIssuer(cert.getIssuerX500Principal().getEncoded());*/
				
				
				/*MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(recipientPrivateKey, providerName));
				MimeMultipart parts=(MimeMultipart) res.getContent();

			    for (int i=0;i<parts.getCount();i++){
			        BodyPart part=parts.getBodyPart(i);
			        if (part.getContentType().contains("application/octet-stream")){
			            //System.out.println(IOUtils.toString((InputStream) part.getContent()));
			            ZipInputStream zin = new java.util.zip.ZipInputStream((InputStream)part.getContent());
			            java.util.zip.ZipEntry entry;
			            while((entry = zin.getNextEntry()) != null) {
			                System.out.println(org.apache.commons.io.IOUtils.toString(zin));
			            }
			        }
			    }*/
			    
			} else {
				
				MimeBodyPart bodyPartEncrypted = getDecryptedPart(message);
				
				/*RecipientId recId = new JceKeyTransRecipientId(cert);
				RecipientInformation recipient = recipientsStore.get(recId);
				decryptedData = recipient.getContent(recipientKey);*/
				
				/*SMIMEEnveloped smimeEnveloped = new SMIMEEnveloped(mimeMessage);
				RecipientInformationStore recipients = smimeEnveloped.getRecipientInfos();
				RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(certificate));

				if (null == recipient)  throw new MessagingException("no recipient");

				JceKeyTransRecipient transportRecipient = new JceKeyTransEnvelopedRecipient(privateKey);
				transportRecipient.setProvider(BouncyCastleProvider.PROVIDER_NAME);
				byte[] decryptBytes =  recipient.getContent(transportRecipient);*/
				
				
				/*JceKeyTransRecipient recipientKey = new JceKeyTransEnvelopedRecipient(recipientPrivateKey)
					.setProvider(providerName); // BouncyCastleProvider.PROVIDER_NAME
				
				byte[] decryptedData = null;
				MimeBodyPart bodyPartEncrypted = null;
				
				// Enveloped Data : https://github.com/bcgit/bc-java/issues/341#issuecomment-635841495
				
				// baos = encryptedData, recipientPrivateKey = decryptionKey
				byte[] encryptedData = baos.toByteArray();
				if (null != encryptedData && null != recipientPrivateKey) {
					CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
					Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
					System.out.println("RecipientInformation encryptedData count: "+recipients.size());
					
					Collection<RecipientInformation> recipients_Store = recipientsStore.getRecipients();
					System.out.println("RecipientInformation recipientsStore count: "+recipients_Store.size());
					
					InputStream ris = null;
					if (recipients.size() > 0) {
						Iterator<RecipientInformation> iterator = recipients.iterator();
						while (iterator.hasNext()) {
							RecipientInformation recipientInfo = iterator.next();
							//KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
							
							RecipientId rid = recipientInfo.getRID();
							System.out.println("RID: "+rid);
							
							try {
								decryptedData = recipientInfo.getContent(recipientKey);
								System.out.println("recipientInfo.getContent : "+decryptedData.length);
							} catch(Exception e) {
								e.printStackTrace();
							}
							
							try {
								CMSTypedStream contentStream = recipientInfo.getContentStream(recipientKey);
								ris = contentStream.getContentStream();
								System.out.println("getContentStream");
							} catch(Exception e) {
								e.printStackTrace();
							}
							
						}
						
						if (decryptedData != null) {
							bodyPartEncrypted = SMIMEUtil.toMimeBodyPart(decryptedData);
						} else if (ris != null) {
							bodyPartEncrypted  = SMIMEUtil.toMimeBodyPart(ris);
						}
					}
					
				}*/
				
				System.out.println("====== enveloped-data : END");
				
				if (bodyPartEncrypted != null) {
					data = readMailContent(bodyPartEncrypted, data, charset);
				} else {
					/*MimeBodyPart decryptedPart = getDecryptedPart(message);
					String mimeType = decryptedPart.getHeader("Content-type", ";");
					System.out.println("mimeType :"+mimeType);*/
				}
			}
			
		} else { // Content-Type ~:~ application/pkcs7-mime; name=smime.p7m; smime-type=signed-data
			//MimeMultipart multipart = (MimeMultipart) message.getContent();
			
			//SMIMESigned signed = new SMIMESigned((MimeMultipart) message.getContent());
			try {
				MimeMessage signedMimeMessage = new MimeMessage((MimeMessage) message);
				MimeMultipart signedMultipart = null;
				SMIMESignedParser signedParser = null; // https://stackoverflow.com/a/57722857/5081877
				
				DigestCalculatorProvider build = new JcaDigestCalculatorProviderBuilder().build();
				if (signedMimeMessage.isMimeType("multipart/signed")) {
					System.out.println("signedMimeMessage : multipart/signed");
					signedMultipart = (MimeMultipart) message.getContent();
					signedParser = new SMIMESignedParser(build, signedMultipart);
				} else if (signedMimeMessage.isMimeType("application/pkcs7-mime")) {
					System.out.println("signedMimeMessage : application/pkcs7-mime");
					signedParser = new SMIMESignedParser(build, signedMimeMessage);
				}
				
				/*signedMimeMessage : application/pkcs7-mime
				Special MSG Exception:IOException reading content.
				org.bouncycastle.cms.CMSException: IOException reading content.
					at org.bouncycastle.cms.CMSUtils.readContentInfo(Unknown Source)
					at org.bouncycastle.cms.CMSUtils.readContentInfo(Unknown Source)
					at org.bouncycastle.cms.CMSSignedData.<init>(Unknown Source)
					at com.java.mail.IMAP_MimeMail.fetchEnvelopedContent(IMAP_MimeMail.java:1012)*/
				
				CMSTypedStream signedContent = signedParser.getSignedContent();
				InputStream signedContentStream = signedContent.getContentStream();
				CMSSignedData signature = new CMSSignedData(signedContentStream); // org.bouncycastle.cms.CMSException: IOException reading content.
				X509Certificate x509Cert = CertsUtil.getX509Cert(security_certificate);
				boolean signatureVerified = signatureVerified(signature, x509Cert);
				System.out.println("***** signatureVerified :"+signatureVerified);
				
				/*
				InputStream signedContentStream = signedContent.getContentStream();
				
				SignerInformationStore sis = signedParser.getSignerInfos();
				Enumeration allHeaders = signedParser.getContent().getAllHeaders();
				System.out.println("SignerInformationStore ===== enumerSigned Headers Start");
				while (allHeaders.hasMoreElements()) {
					Header header = (Header) allHeaders.nextElement();
					System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
				}
				System.out.println("SignerInformationStore ===== enumerSigned Headers End");*/
				
				// signatureVerified(
				
				boolean isSignSuccess = false;
				org.bouncycastle.util.Store certs = (org.bouncycastle.util.Store) signedParser.getCertificates();
				//org.bouncycastle.util.CollectionStore certs = (CollectionStore) signedParser.getCertificates();
				SignerInformationStore signers = signedParser.getSignerInfos();
				Collection c = signers.getSigners();
				Iterator it = c.iterator();
				while (it.hasNext()) {
					SignerInformation signer = (SignerInformation) it.next();
					SignerId sid = signer.getSID();
					System.out.println("signer.getSID() : "+ sid);
					Collection certCollection = ((org.bouncycastle.util.Store) certs).getMatches(sid);
					Iterator certIt = certCollection.iterator();
					X509Certificate certSign = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) certIt.next());
					try {
						isSignSuccess = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certSign));
					} catch (Exception e) {
						System.out.println("Error occured during verification: "+ e.getMessage());
						e.printStackTrace();
					}
				}
				
				System.out.println("isSignSuccess : "+isSignSuccess);
				
				// MimeMessage signedMimeMessage = new MimeMessage((MimeMessage) message);
				/*MimeMultipart multipart = null;
				try {
					multipart = (MimeMultipart) signedMimeMessage.getContent();
				} catch (Exception e) {
					e.printStackTrace();
				}*/
				
				SMIMESigned signed = new SMIMESigned(signedMimeMessage);
				MimeBodyPart bodyPartSigned =(MimeBodyPart) signed.getContent();
				
				if (isSignSuccess ) {
					
					Object content = bodyPartSigned.getContent();
					
					Enumeration enumerSigned = bodyPartSigned.getAllHeaders();
					System.out.println("===== enumerSigned Headers Start");
					while (enumerSigned.hasMoreElements()) {
						Header header = (Header) enumerSigned.nextElement();
						System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
					}
					System.out.println("===== enumerSigned Headers End");
					
					
					if (content instanceof MimeMultipart) {
						signedMultipart = (MimeMultipart) bodyPartSigned.getContent();
						
						int countParts = signedMultipart.getCount();
						System.out.println("====== SC Count:"+countParts);
						
						for (int j = 0; j < countParts; j++)
						{
								System.out.println("----- Signed Content");
								BodyPart bp = signedMultipart.getBodyPart(j);
								if (j == 0) {
									System.out.println("----- Signed Certificate Content");
								}
								
								if (j != 0 ) { // SKIP Signer part - j+1 < countParts
									//Object signedContent = bp.getContent();
									//if (signedContent instanceof MimeMultipart) {
										
										if (bp.getFileName() != null && bp.getFileName().length() > 0)
										{
											data.setAttachmentName(bp.getFileName());
											data.setAttachmentDataStream(bp.getInputStream());
//											InputStreamReader reader = new InputStreamReader(bp.getInputStream());
//											data.setAttachmentData(reader);
										}
										else
										{
											BufferedReader reader = new BufferedReader(
													new InputStreamReader(bp.getInputStream(), charset));
											StringBuffer sb = new StringBuffer();
											while (reader.ready())
											{
												sb.append(reader.readLine());
												sb.append(System.getProperty("line.separator"));
											}
											String bodyString = sb.toString();
											data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
											data.setFpId(null);
											data.setHttpDetail(null);
										}
									
									//} else {
									//	System.out.println("----- Signed Content Part contains no Attachemtns");
									//}
							}
						}
					}
					
					
				}
				
				
				/*if (verifySignature(mimeMsg)) {
					System.out.println("verification succeeded");
				} else {
					System.out.println("verification failed");
				}
				MimeMessage signed = new MimeMessage((MimeMessage) message);*/
				
				/*Object content = signed.getContent();  
				if (content instanceof String)  
				{  
					String body = (String)content;  
					System.out.println("String : "+body);
				}  
				else if (content instanceof Multipart)  
				{  
					Multipart multipart = (Multipart)content;  
					System.out.println("Multipart : ");  
				} else {
				}*/
				
				
				
			   // MimeMultipart multipart = (MimeMultipart) signed.getContent();
				// MimeBodyPart content = (MimeBodyPart) signed.getContent();
				// System.out.println("Content: " + content.getContent());
			
				System.out.println("Data : "+data);
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		}
		return data;
		/**/
		
		
		/*MimeMultipart parts = (MimeMultipart) res.getContent();

		for (int i = 0; i < parts.getCount(); i++) {
			final BodyPart part = parts.getBodyPart(i);
			if (part.getContent() instanceof Multipart) {
				multipart = (Multipart) part.getContent();
			}
		}*/
	}
	
	protected String recipientToString(RecipientInformation recipient) {
		  if (recipient instanceof KeyTransRecipientInformation) {
		    KeyTransRecipientId rid = (KeyTransRecipientId)recipient.getRID();
		    return "Issuer=" + rid.getIssuer() + ", serial number=" + rid.getSerialNumber() + ", key encryption algorithm OID=" + recipient.getKeyEncryptionAlgOID();
		  } else {
		    return "not a KeyTransRecipientInformation: " + recipient.getRID().getType();
		  }
		}
	
	public static AckMailData readMailContent(MimeBodyPart bodyPartEncrypted, AckMailData data, String charset) throws MessagingException, IOException {
		
		System.out.println("----- Special Content");
		
		Object content = bodyPartEncrypted.getContent();
		
		if (content instanceof MimeMultipart) {
			MimeMultipart multipart = (MimeMultipart) bodyPartEncrypted.getContent();
			
			int countParts = multipart.getCount();
			System.out.println("----- MimeMultipart Content, Count:"+countParts); // 2
			for (int j = 0; j < countParts; j++) {
				MimeBodyPart bp = (MimeBodyPart) multipart.getBodyPart(j);
				
				Enumeration enumerbp = bp.getAllHeaders();
				System.out.println("===== --- Headers Start");
				while (enumerbp.hasMoreElements()) {
					Header header = (Header) enumerbp.nextElement();
					System.out.printf("%s ~:~ %s%n", header.getName(), header.getValue());
				}
				System.out.println("===== --- Headers End");
				
				Object signedContent = bp.getContent();
				if (signedContent instanceof MimeMultipart) {
					System.out.println("----- Signed Content");
					
					if (j+1 < countParts) { // SKIP Signer part
						data = readMailContent(bp, data, charset);
					} else {
						System.out.println("----- Signed Content Part contains no Attachemtns");
					}
					j = j+1;
				} else {
					System.out.println("----- Multipart Content");
					if (bp.getFileName() != null && bp.getFileName().length() > 0) {
						data.setAttachmentName(bp.getFileName());
						data.setAttachmentDataStream(bp.getInputStream());
//						InputStreamReader reader = new InputStreamReader(bp.getInputStream());
//						data.setAttachmentData(reader);
					} else {
						BufferedReader reader = new BufferedReader(
								new InputStreamReader(bp.getInputStream(), charset));
						StringBuffer sb = new StringBuffer();
						
						while (reader.ready()) {
							sb.append(reader.readLine());
							sb.append(System.getProperty("line.separator"));
						}
						String bodyString = sb.toString();
						data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
						data.setFpId(null);
						data.setHttpDetail(null);
					}
				}
			}
		} else if (content instanceof String) {
			System.out.println("===== String Content");
			String bodyString = (String) content;
			data.setBody(bodyString.length() > 4000 ? bodyString.substring(0, 4000) : bodyString);
			data.setAttachmentName(null);
			//data.setAttachmentData(null);
			data.setFpId(null);
			data.setHttpDetail(null);
		} /*else if (content instanceof BASE64DecoderStream) {  https://stackoverflow.com/a/2765874/5081877
			BASE64DecoderStream base64DecoderStream = (BASE64DecoderStream) part.getContent();
			byte[] byteArray = IOUtils.toByteArray(base64DecoderStream);
			byte[] encodeBase64 = Base64.encodeBase64(byteArray);
			base64Content[0] = new String(encodeBase64, "UTF-8");
			base64Content[1] = getContentTypeString(part);
		}*/
		
		return data;
	}
	/**
	 * Verify the passed in CMS signed data, return false on failure.
	 *
	 * @param cmsData a CMSSignedData object.
	 * @return true if signature checks out, false if there is a problem with the signature or the path to its verifying certificate.
	 */
	public static boolean signatureVerified(CMSSignedData cmsData, X509Certificate x509Cert)  {
		Store certs = (Store) cmsData.getCertificates();
		SignerInformationStore signers = cmsData.getSignerInfos();

		Collection c = signers.getSigners();
		Iterator it = c.iterator();

		SignerInformation signer = (SignerInformation)it.next();
		try {
			PKIXCertPathBuilderResult result = checkCertPath(signer.getSID(), certs, x509Cert);
			X509Certificate cert = (X509Certificate)result.getCertPath().getCertificates().get(0);
			return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
		} catch (Exception e) {
			return false;
		}
	}
	private static PKIXCertPathBuilderResult checkCertPath(SignerId signerId, Store certs, X509Certificate x509Cert) throws IOException, GeneralSecurityException {
		CertStore store = new JcaCertStoreBuilder().setProvider("BC").addCertificates((org.bouncycastle.util.Store) certs).build();

		CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX","BC");
		X509CertSelector targetConstraints = new X509CertSelector();

		targetConstraints.setIssuer(signerId.getIssuer().getEncoded());
		targetConstraints.setSerialNumber(signerId.getSerialNumber());

		PKIXBuilderParameters params = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(x509Cert, null)), targetConstraints);

		params.addCertStore(store);
		params.setRevocationEnabled(false);			// TODO: CRLs?

		return (PKIXCertPathBuilderResult)pathBuilder.build(params);
	}
}
