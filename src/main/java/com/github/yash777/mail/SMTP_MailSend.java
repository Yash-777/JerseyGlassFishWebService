package com.github.yash777.mail;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.Deflater;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.MailcapCommandMap;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMessage.RecipientType;
import javax.mail.internet.MimeMultipart;

import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.w3c.dom.Document;

import com.sun.mail.smtp.SMTPMessage;
import com.sun.mail.smtp.SMTPTransport;

import net.markenwerk.utils.mail.smime.SmimeKey;
import net.markenwerk.utils.mail.smime.SmimeUtil;

// Outlook certificate error: Digital ID name cannot be found by underlying security system
// https://answers.microsoft.com/en-us/msoffice/forum/all/outlook-certificate-error-digital-id-name-cannot/1c36d919-91cf-4bc9-a7cc-aeb09ae37084

// Import the certificate with CRYPTAPI Private Key: Yashwanth@777
// https://stackoverflow.com/questions/34812897/how-to-suppress-an-application-is-requesting-access-to-a-protected-item-popup
// https://docs.microsoft.com/en-us/archive/blogs/pki/what-is-a-strong-key-protection-in-windows

// NoClassDefFoundError: com/sun/activation/registries/LogSupport - <dependency> javax.activation - activation - 1.1.1
public class SMTP_MailSend {
	static String configFile = "EmailConf.xml";
	
	boolean isSigned, isEncrypted, isStoreMessage, isCompressedGZIP;
	public SMTP_MailSend (boolean isSigned, boolean isEncrypted, boolean isStoreMessage, boolean isCompressedGZIP) {
		this.isSigned = isSigned;
		this.isEncrypted = isEncrypted;
		this.isStoreMessage = isStoreMessage;
		this.isCompressedGZIP = isCompressedGZIP;
	}
	
	private final static Log log = LogFactory.getLog(SMTP_MailSend.class);
	//String security_privatekey = ""; // "Baeldung.p12";
	//String security_certificate = ""; // "Baeldung.cer";
	static String outputMailFile = "C:/Yash/JMail/SendingMessage_<CurrDate>.eml";// .eml .msg .txt
	
	/*static PrivateKey recipientPrivateKey_Stats;
	static X509Certificate cert_stats;*/
	
	protected void setEncryptionKeyData(String resourceIdentifier) throws MailPreparingException, IOException {
		//InputStream is = rp.getResource("security.certificate", resourceIdentifier).getContent();
		InputStream cerFileStream = fileObj.getCerFileStream(true, resourceIdentifier);// security_certificate
		recipientCertificate = getX509Certificate(cerFileStream);
		cerFileStream.close();
	}
	
	protected X509Certificate getX509Certificate(InputStream inputStream) {
		X509Certificate x509Certificate = null;
		CertificateFactory certificateFactory = null;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", "BC");
			x509Certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
		} catch (CertificateException e) {
			log.error(e, e);
		} catch (NoSuchProviderException e) {
			log.error(e, e);
		}
		return x509Certificate;
	}
	protected void setSignerKeyData(String resourceIdentifier, String password) throws MailPreparingException, IOException {
		// security.privatekey
		InputStream cerFileStream = fileObj.getCerFileStream(true, resourceIdentifier); //security_privatekey
		HashMap certificateDataHashMap = buildCertificateAndGetPrivateKey(cerFileStream, password);
		signerPrivateKey = (PrivateKey) certificateDataHashMap.get("certificatePrivateKey");
		signerCertificate = (X509Certificate) certificateDataHashMap.get("certificate");
		cerFileStream.close();
		
		/*if (signerCertificatesChain == null) {
			throw new MailPreparingException("", "Error while reading the certificate: " + resourceIdentifier);
		}*/
	}
	
	static FileOpreations fileObj = new FileOpreations();
	static SMTP_Cong_XML configSMTP;
	//static boolean isEncryptMsg = true;
	
	public static void main(String[] args) throws Exception {
		
		/*URL resourceMail = javax.mail.internet.ParameterList.class.getResource("javax.mail.internet.Paramete‌rList.class");
		System.out.println("resourceMail: "+resourceMail);
		URL resourceSUN = com.sun.xml.messaging.saaj.packaging.mime.internet.ParameterList.class.getResource("com.sun.xml.messaging.saaj.packaging.mime.internet.Paramete‌rList.class");
		System.out.println("resourceSUN: "+resourceSUN);*/
		
		//SMTP_Cong_JAVA conf = new SMTP_Cong_JAVA();
		//System.out.println(conf.additionalRecipients.toString());
		SMTP_MailSend obj = new SMTP_MailSend(true, true, true, true);
		obj.mailSend();
	}
	
	public void sendMail(Session session, String from, String to, String subject, String content, SmimeKey mimeKey) throws Exception {
		MimeMessage message = new MimeMessage(session);
		message.setFrom(new InternetAddress(from));
		message.setRecipient(RecipientType.TO, new InternetAddress(to));
		message.setSubject(subject);
		message.setContent(content, "text/plain; charset=utf-8");
		MimeMessage encryptedSignedMessage = encryptMessage(session, signMessage(session, message, from, mimeKey), to, mimeKey);
		Transport.send(encryptedSignedMessage);
	}
	private MimeMessage signMessage(Session session, MimeMessage message, String from, SmimeKey smimeKey) throws Exception {
		//SmimeKey smimeKey = getSmimeKeyForSender(from);
		return SmimeUtil.sign(session, message, smimeKey);
	}
	private MimeMessage encryptMessage(Session session, MimeMessage message, String to, SmimeKey smimeKey) throws Exception {
		//X509Certificate certificate = getCertificateForRecipient(to);
		return SmimeUtil.encrypt(session, message, smimeKey.getCertificate());
	}
	/*public void mailSend2() throws Exception {
		SmimeKey mimeKey = new SmimeKey(recipientPrivateKey, cert);
		sendMail()
	}*/
	
	public void mailSend() throws Exception {
		
		InputStream xmlConfigFileStream = fileObj.getCerFileStream(true, configFile);
		String xmlContent = fileObj.getDiskFileStream_Lines(xmlConfigFileStream);
		System.out.println("XML:"+ xmlContent);
		
		// SMTP_Cong_XML config
		DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_HHmmss");
		String reportDate = dateFormat.format(new Date());
		
		outputMailFile = outputMailFile.replace("<CurrDate>", reportDate);
		
		Document doc = fileObj.getDocument(xmlContent.trim());
		configSMTP = new SMTP_Cong_XML(doc);
		System.out.println("Config:"+configSMTP.toString());
		
		// Object Level changes.
		configSMTP.setSigned(isSigned);
		configSMTP.setDoEncrypt(isEncrypted);
		System.out.println("Config:"+configSMTP.toString());
		
		//security_privatekey = configSMTP.getSignerKey();
		//security_certificate = configSMTP.getRecipientCertificate();
		
		String fileName = "MailSampleAttachement_"+reportDate+".xml"; // csv, xml
		if (fileName != null) {
			AttachementFiles att = new AttachementFiles();
			att.setName(fileName);
			
			if (fileName.endsWith(".csv")) {
				att.setContentType("text/csv");
				ByteArrayOutputStream outStream = att.getOutStream();
				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outStream);
				for (int i = 0; i < 5; i++) {
					bufferedOutputStream.write("CSV DATA\n".getBytes());
				}
				bufferedOutputStream.flush();
			}
			if (fileName.endsWith(".xml")) {
				att.setContentType("text/xml");
				String xmlContentStr = "<tem:Add xmlns:tem=\"http://tempuri.org/\"><tem:intA>2</tem:intA><tem:intB>4</tem:intB></tem:Add>";
				ByteArrayOutputStream outStream = att.getOutStream();
				
				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outStream);
					bufferedOutputStream.write( xmlContentStr.getBytes(Charset.forName("UTF-8")) );
				bufferedOutputStream.flush();
			}
			
			// https://cloud.google.com/appengine/docs/standard/php/mail/mail-with-headers-attachments
			if (isCompressedGZIP) {
				
				ByteArrayOutputStream outStream = (ByteArrayOutputStream) att.getOutStream();
				// OutStream to InputStream -  https://stackoverflow.com/a/41888647/5081877
				byte[] bytes = outStream.toByteArray();
				System.out.println("Payload Bytes:"+ new String(bytes) );
				InputStream inputStream = new ByteArrayInputStream(bytes);
				
				ByteArrayOutputStream outStreamGZIP = new ByteArrayOutputStream();
				compressCommons(inputStream, fileName, outStreamGZIP);
				
				fileName += ".gz";
				att.setName(fileName);
				att.setContentType("application/octet-stream"); // application/octet-stream, application/x-gzip
				att.setOutStream(outStreamGZIP);
			}
			addDeliverable(att);
		}
		
		config = configSMTP;
		send();
	}
	public void compressCommons(InputStream streamSrc, String fileName, OutputStream gipStream) throws IOException {
		GzipParameters parameters = new GzipParameters();
		parameters.setCompressionLevel(Deflater.BEST_SPEED);
		parameters.setFilename( fileName );
		parameters.setModificationTime( (new java.util.Date()).getTime() );
		
		GzipCompressorOutputStream out = new GzipCompressorOutputStream(gipStream, parameters); // zipFile
		
		byte[] buf = new byte[10240];
		while (true) {
			int len = streamSrc.read(buf);
			if (len <= 0) {
				break;
			}
			out.write(buf, 0, len);
		}
		out.flush();
		out.close();
		streamSrc.close();
	}
	
	public void send() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		//KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		
		MimeMessage finalMessage = null;
		ByteArrayOutputStream out = null;
		ByteArrayInputStream byteArrayInputStream = null;
		
		initializeMessage();
		
		try {
			// set the Date: header
			message.setSentDate(new Date());
			
			Multipart multipartContent = new MimeMultipart();
			if (messageText != null) {
				multipartContent.addBodyPart(messageText);
			}
			
			if (attachments != null && attachments.size() > 0) {
				for (Iterator<AttachementFiles> it = attachments.iterator(); it.hasNext();)
				{
					AttachementFiles attachment = (AttachementFiles) it.next();
					MimeBodyPart attachmentMimeBody = new MimeBodyPart();
					InputStream is = attachment.getContent();
					log.info("createMimeBodyPart for Attachment contentTYpe" + attachment.getContentType() + " name::"
							+ attachment.getName());
					log.info("available byte in attachements" + is.available());
					DataSource attachementDataSource = 
							new ByteArrayDataSource(is, attachment.getContentType(), attachment.getName());
					attachmentMimeBody.setDataHandler(new DataHandler(attachementDataSource));
					attachmentMimeBody.setFileName(attachementDataSource.getName());
					
					multipartContent.addBodyPart(attachmentMimeBody);
				}
			}
			
			message.setContent(multipartContent);
			System.out.println("additionalRecipients:"+additionalRecipients);
			if (additionalRecipients != null) {
				for (Iterator it = additionalRecipients.iterator(); it.hasNext();) {
					String to = (String) it.next();
					System.out.println("To:"+to);
					try {
						message.addRecipient(RecipientType.TO, new InternetAddress(to));
					} catch (AddressException e) {
						throw new MailPreparingException("", "Adresse im to:-Feld hat falsches Format: " + to, e);
					} catch (MessagingException e) {
						throw new MailPreparingException("", MESSAGINGEXCEPTION_MESSAGE, e);
					}
				}
			}
			
			out = new ByteArrayOutputStream();
			Enumeration headers = message.getAllHeaderLines();
			
			if (config.getSigned().booleanValue() || config.getDoEncrypt().booleanValue()) {
				initializeSMIME();
			} else {
				System.out.println("Noramal Mail written to OUT");
				message.writeTo(out);
			}
			
			System.out.println("getSigned : "+config.getSigned().booleanValue());
			System.out.println("getDoEncrypt : "+config.getDoEncrypt().booleanValue());
			
			
			System.out.println("getSignModeDetached : "+config.getSignModeDetached().booleanValue());
			if (!config.getDoEncrypt().booleanValue()) {
				config.setSignModeDetached(false);
			}
			System.out.println("getSignModeDetached : "+config.getSignModeDetached().booleanValue());
			
			if (config.getSigned().booleanValue()) {
				setSignerKeyData(config.getSignerKey(), config.getSignerKeyPassword());
				SMIMESignedGenerator signer = createSignerUsingBouncyCastle();
				
				MimeMessage signedMessage = null;
				MimeMultipart multipart = null;
				MimeBodyPart mimeBodyPart = null;
				
				if (config.getSignModeDetached().booleanValue()) {
					multipart = getDetachedMimeMultiPart(signer);
					signedMessage = getSingnedMessage(headers, multipart, multipart.getContentType());
				} else {
					mimeBodyPart = getEncapsulatedMimeBodyPart(signer);
					signedMessage = getSingnedMessage(headers, mimeBodyPart, mimeBodyPart.getContentType());
				}
				
				if (config.getDoEncrypt().booleanValue()) {
					setEncryptionKeyData(config.getRecipientCertificate());
					MimeBodyPart encryptedPart = getEncryptedPart(signedMessage);
					System.out.println("encryptedPart : "+encryptedPart);
					encryptedPart.writeTo(out);
				} else {
					if (config.getSignModeDetached().booleanValue()) {
						multipart.writeTo(out);
					} else {
						mimeBodyPart.writeTo(out);
					}
				}
			}
			
			/**
			 * Create a new MimeMessage that contains the encrypted and signed
			 * content
			 */
			byteArrayInputStream = new ByteArrayInputStream(out.toByteArray());
			finalMessage = new MimeMessage(session, byteArrayInputStream);
			
			/** Set all original MIME headers in the encrypted message */
			if (config.getSigned().booleanValue()) {
				headers = message.getAllHeaderLines();
				while (headers.hasMoreElements()) {
					String headerLine = (String) headers.nextElement();
					/**
					 * Make sure not to override any content-* headers from the  original message
					 */
					log.info("Headers::" + headerLine);
					if (!Strings.toLowerCase(headerLine).startsWith("content-")) {
						finalMessage.addHeaderLine(headerLine);
					}
				}
			}
			finalMessage.saveChanges();
			
		} catch (MessagingException e) {
			throw new MailPreparingException("Error creating mail for shipping", e);
		} catch (SMIMEException e) {
			log.error(e, e);
		} catch (CMSException e) {
			System.out.println("CMSException : "+ e.getMessage());
			e.printStackTrace();
			log.error(e, e);
		} catch (IOException e) {
			log.error(e, e);
		} finally {
			try {
				if (out != null) {
					out.close();
					out = null;
				}
				if (byteArrayInputStream != null) {
					byteArrayInputStream.close();
					byteArrayInputStream = null;
				}
			} catch (IOException e) {
				log.error(e, e);
			}
		}
		System.out.println("isStoreMessage:"+isStoreMessage);
		

		if (isStoreMessage) {
			// https://github.com/protocol7/smime-java-example/blob/master/src/main/java/com/protocol7/smime/Sign.java
			/*
			SmimeKey mimeKey = new SmimeKey(recipientPrivateKey_Stat, cert_stat);
			String fromAddr = config.getFrom(), toAddr = config.getTo();
			
			MimeMessage message = new MimeMessage(session);
			message.setFrom(new InternetAddress(fromAddr));
			message.setRecipient(RecipientType.TO, new InternetAddress(toAddr));
			message.setSubject("Test Mail SMIME");
			message.setContent("Sample String Body Content", "text/plain; charset=utf-8");
			MimeMessage encryptedSignedMessage = encryptMessage(session, signMessage(session, message, fromAddr, mimeKey), toAddr, mimeKey);
			encryptedSignedMessage.writeTo(System.out);
			encryptedSignedMessage.writeTo(new FileOutputStream(outputMailFile));
			*/
			
			SMTPMessage msg = new SMTPMessage(finalMessage);
			msg.setReplyTo(message.getAllRecipients());
			msg.setNotifyOptions(SMTPMessage.NOTIFY_SUCCESS + SMTPMessage.NOTIFY_FAILURE);
			msg.setReturnOption(SMTPMessage.RETURN_HDRS);
			
			msg.writeTo(System.out);
			msg.writeTo(new FileOutputStream(outputMailFile)); // .eml
			
		} else {
			
		/* send the message */
		try {
			/** Transport.send(message); */
			SMTPTransport t = (SMTPTransport) session.getTransport("smtp");
			try {

				if (config.isSmtpAuth()) {
					log.info("inside onfig.isSmtpAuth()");
					t.connect(config.getRelayHost(), Integer.parseInt(props.getProperty("mail.smtp.port", "25")),
							config.getSmtpAuthLogin(), config.getSmtpAuthPassword());
				} else {
					log.info("inside else of  onfig.isSmtpAuth()");
					t.connect();
				}

				if (config.isDeliveryReceipt()) {
					log.info("inside onfig.isDeliveryReceipt()");
					SMTPMessage msg = new SMTPMessage(finalMessage);
					msg.setReplyTo(message.getAllRecipients());
					msg.setNotifyOptions(SMTPMessage.NOTIFY_SUCCESS + SMTPMessage.NOTIFY_FAILURE);
					msg.setReturnOption(SMTPMessage.RETURN_HDRS);

					sendMessage(t, msg, msg.getAllRecipients());
				} else {
					log.info("inside else config.isDeliveryReceipt()" + finalMessage.getAllRecipients());
					sendMessage(t, finalMessage, message.getAllRecipients());
				}
			} finally {
				t.close();
			}
		} catch (MessagingException e) {
			throw new MailPreparingException("Fehler beim Versand der Mail.", e);
		}

		}
	}
	
	private void sendMessage(Transport transport, MimeMessage message, Address[] recipients) throws MessagingException
	{

		log.info("inside sendMessage");
		StringBuilder sb = new StringBuilder();
		sb.append("Sending e-mail to recipients: ").append(Arrays.toString(recipients)).append(", subject: ")
				.append(message.getSubject());

		boolean firstProperty = true;
		sb.append(", session properties: [");
		for (Entry<Object, Object> property : session.getProperties().entrySet()) {
			String key = String.valueOf(property.getKey());
			String value = String.valueOf(property.getValue());

			if (key.toLowerCase().contains("password")) {
				value = value.replaceAll(".", "*");
			}

			if (firstProperty) {
				firstProperty = false;
			} else {
				sb.append(", ");
			}

			sb.append(key).append("=").append(value);
		}
		sb.append("]");

		log.info("Message::::::" + sb.toString());
		transport.sendMessage(message, recipients);
	}
	
	private MimeMultipart getDetachedMimeMultiPart(SMIMESignedGenerator signer)
			throws MessagingException, SMIMEException
	{
		MimeMultipart mimeMultipart = null;

		mimeMultipart = signer.generate(message);

		return mimeMultipart;

	}

	private MimeBodyPart getEncapsulatedMimeBodyPart(SMIMESignedGenerator signer)
			throws MessagingException, SMIMEException
	{
		MimeBodyPart mimeBodyPart = null;

		mimeBodyPart = signer.generateEncapsulated(message);

		return mimeBodyPart;

	}
	private MimeMessage getSingnedMessage(Enumeration headers, Object mimeObjectPart, String contentType)
			throws MessagingException
	{
		MimeMessage signedMessage = new MimeMessage(session);

		/** Set all original MIME headers in the signed message */
		while (headers.hasMoreElements())
		{
			signedMessage.addHeaderLine((String) headers.nextElement());
		}

		signedMessage.setContent(mimeObjectPart, contentType);
		signedMessage.saveChanges();
		return signedMessage;
	}
	
	private MimeBodyPart getEncryptedPart_OLD(MimeMessage message) throws SMIMEException, CMSException, CertificateEncodingException, IllegalArgumentException
	{
		try {
			SMIMEEnvelopedGenerator encrypter = createEncrypterUsingBouncyCastle();
			return encrypter.generate(message, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());
		
			/*SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator ();
			CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator (); // https://stackoverflow.com/q/36518988/5081877
		    RecipientInfoGenerator recipientGenerator = new JceKeyTransRecipientInfoGenerator (recipientCertificate).setProvider ("BC");
		    gen.addRecipientInfoGenerator (recipientGenerator);
		
		    OutputEncryptor outputEncryptor = new JceCMSContentEncryptorBuilder (CMSAlgorithm.SHA256).build ();
		    MimeBodyPart envData        = gen.generate (message, outputEncryptor);
		    		// gen.generate (new CMSProcessableByteArray (buffer), outputEncryptor);
		
		    return envData;*/
		} catch (CMSException e)  {
			e.printStackTrace();
			throw new CMSException(e.getMessage());
		}
	
	}	
	/*
	Please note the following requirements for the encryption:
* Content encryption
Only the following methods are valid:
AES-128 CBC, AES-192 CBC oder AES-256 CBC (IETF RFC 3565)

* Key encryption
Only RSAES-OAEP (IETF RFC 8017) is valid. 
Based on first experiences, please note that RSA does not fulfill the requirements! 
As hash functions, only SHA-256 and SHA-512 are valid. The key length has to be at least 2048 Bit.
	 */
	private MimeBodyPart getEncryptedPart(MimeMessage message) throws SMIMEException, CMSException, CertificateEncodingException, IllegalArgumentException
	{
try {
	
	/* OLD CODE
	 * SMIMEEnvelopedGenerator encrypter = createEncrypterUsingBouncyCastle();
	return encrypter.generate(message,
			new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());
	 */

		//SMIMEEnvelopedGenerator encrypter = createEncrypterUsingBouncyCastle();
		
		/*
		SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator ();
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator (); - https://stackoverflow.com/q/36518988/5081877
	    RecipientInfoGenerator recipientGenerator = new JceKeyTransRecipientInfoGenerator (recipientCertificate).setProvider ("BC");
	    gen.addRecipientInfoGenerator (recipientGenerator);

	    OutputEncryptor outputEncryptor = new JceCMSContentEncryptorBuilder (CMSAlgorithm.SHA256).build ();
	    MimeBodyPart envData        = gen.generate (message, outputEncryptor);
	    		// gen.generate (new CMSProcessableByteArray (buffer), outputEncryptor);

	    return envData;*/
	
	/*"alg": "RSA-OAEP-256",
	  "enc": "A128GCM",*/
//	X509Certificate recipientCert = recipientCertificate;
//	AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP);
//	
//	String symmetricWrappingAlg = "1.2.840.113549.1.1.7"; //"RSAES-OAEP";
//	int keySizeInBits = 1024;
	/*try {
		KeyFactory factory = KeyFactory.getInstance("RSA-OAEP-256");
		symmetricWrappingAlg = factory.getAlgorithm();
		System.out.println("symmetricWrappingAlg : "+symmetricWrappingAlg);
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}*/
	
	// https://stackoverflow.com/questions/38686704/how-to-use-bouncycastle-lightwigth-api-to-generate-cms-enveloped-data
	
	String digest = "SHA-256";
	String mgfDigest = "SHA-256";
	
	// https://stackoverflow.com/a/56901605/5081877
	// Note that at JcaAlgorithmParametersConverter is available since BC 1.50.
	JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
	OAEPParameterSpec oaepParameters = new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(mgfDigest), PSource.PSpecified.DEFAULT);
	AlgorithmIdentifier idRsaOaep = null;
	try {
		idRsaOaep = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepParameters);
		System.out.println("AlgorithmIdentifier : "+idRsaOaep.toString());
	} catch (InvalidAlgorithmParameterException e) {
		e.printStackTrace();
	}

	// Generator for my CMS enveloped data  CMSEnvelopedDataGenerator envelopedDataGen = new CMSEnvelopedDataGenerator();
	SMIMEEnvelopedGenerator envelopedDataGen = new SMIMEEnvelopedGenerator();
		envelopedDataGen.addRecipientInfoGenerator(
						//new JceKeyTransRecipientInfoGenerator(recipientCertificate).setProvider("BC"));
				new JceKeyTransRecipientInfoGenerator(recipientCertificate, idRsaOaep).setProvider("BC"));
				//new JceKTSKeyTransRecipientInfoGenerator(recipientCert, idRsaOaep, keySizeInBits).setProvider("BC"));
		
		//ASN1ObjectIdentifier encryptionOID = CMSAlgorithm.AES256_CBC;
		//String encryptionOID = SMIMEEnvelopedGenerator.AES256_CBC;
		//int keySize = 2048; 
		/** Encrypt the message */
		return envelopedDataGen.generate(message,
				// ASN1ObjectIdentifier    RC2_CBC                 = encryptionAlgorithm.branch("2");
				// keySize:2048 org.bouncycastle.cms.CMSException: unable to initialize cipher: 128
				// Caused by: java.lang.ArrayIndexOutOfBoundsException: 128 - at org.bouncycastle.crypto.engines.RC2Engine.generateWorkingKey(Unknown Source)
				// https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionsmimecapabilities
				// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
				// RC2 algorithm in CBC mode. The key length is variable from 40 to 128 bits.
				//new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());  // Tried ones 40/128
				//new JceCMSContentEncryptorBuilder(CMSAlgorithm.SHA256, 2048).setProvider("BC").build());
				
				// ASN1ObjectIdentifier  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.intern();
				// 
				// 2048: java.lang.IllegalArgumentException: incorrect keySize for encryptionOID passed to builder.
				// at org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder.<init>(Unknown Source)
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC, 256).setProvider("BC").build()); // 256
				

} catch (CMSException e)  {
	e.printStackTrace();
	throw new CMSException(e.getMessage());
}

}
	
	protected SMIMEEnvelopedGenerator createEncrypterUsingBouncyCastle()
	{

		SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
		try {
			if (recipientCertificate != null)
			{
				encrypter.addRecipientInfoGenerator(
						new JceKeyTransRecipientInfoGenerator(recipientCertificate).setProvider("BC"));
			}
			else
			{
				log.info("recipientCertificate::" + recipientCertificate);
				throw new Exception("recipientCertificate::" + recipientCertificate);
			}
		} catch (CertificateEncodingException e) {
			log.error(e, e);
		} catch (IllegalArgumentException e) {
			log.error(e, e);
		} catch (Exception e) {
			log.error(e, e);
		}

		return encrypter;
	}
	protected HashMap<String, Object> buildCertificateAndGetPrivateKey(InputStream is, String password)
			throws MailPreparingException
	{
		HashMap<String, Object> certificateDataHashMap = new HashMap<String, Object>();
		KeyStore keystore;
		try {
			// org.apache.catalina.loader.WebappClassLoaderBase.checkStateForResourceLoading Illegal access:
			// this web application instance has been stopped already. YASH: https://stackoverflow.com/a/61952755/5081877
			keystore = KeyStore.getInstance("PKCS12", "BC");

			if (password == null)
			{
				keystore.load(is, null);
			}
			else
			{
				keystore.load(is, password.toCharArray());
			}

			Enumeration<String> keyStoreAliasEnum = keystore.aliases();
			PrivateKey privateKey = null;
			String alias = null;
			if (keyStoreAliasEnum.hasMoreElements())
			{
				alias = keyStoreAliasEnum.nextElement();
				if (password != null)
				{
					privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
				}
			}

			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			Certificate certificate = keystore.getCertificate(alias);
			ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
			X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(bais);
			log.info("**************************************************************************************");

			Certificate[] chain = (Certificate[]) keystore.getCertificateChain(alias);

			if (chain != null) {
				signerCertificatesChain = new X509Certificate[chain.length];
				for (int i = 0; i < chain.length; i++) {
					signerCertificatesChain[i] = (X509Certificate) chain[i];
				}
			}
			
			
			/*
			 * signerCertificates = new X509Certificate[1];
			 * signerCertificates[0] = x509Certificate;
			 */
			certificateDataHashMap.put("certificate", x509Certificate);
			certificateDataHashMap.put("certificatePrivateKey", privateKey);
			
		} catch (KeyStoreException e) {
			log.error(e, e);
		} catch (NoSuchProviderException e) {
			log.error(e, e);
		} catch (NoSuchAlgorithmException e) {
			log.error(e, e);
		} catch (CertificateException e) {
			log.error(e, e);
		} catch (IOException e) {
			log.error(e, e);
		} catch (UnrecoverableKeyException e) {
			log.error(e, e);
		}

		return certificateDataHashMap;
	}

	/** Create the SMIMESignedGenerator */
	protected SMIMESignedGenerator createSignerUsingBouncyCastle()
	{
		SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
		capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
		capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
		capabilities.addCapability(SMIMECapability.dES_CBC);
		//capabilities.addCapability(SMIMECapability.aES256_CBC);

		/*
HTTP Status 500 – Internal Server Error
Type Exception Report

Message org.glassfish.jersey.server.ContainerException: java.lang.NoSuchFieldError: dES_EDE3_CBC

Description The server encountered an unexpected condition that prevented it from fulfilling the request.

Exception

javax.servlet.ServletException: org.glassfish.jersey.server.ContainerException: java.lang.NoSuchFieldError: dES_EDE3_CBC
	org.glassfish.jersey.servlet.WebComponent.serviceImpl(WebComponent.java:432)
	org.glassfish.jersey.servlet.WebComponent.service(WebComponent.java:370)
	org.glassfish.jersey.servlet.ServletContainer.service(ServletContainer.java:389)
	org.glassfish.jersey.servlet.ServletContainer.service(ServletContainer.java:342)
	org.glassfish.jersey.servlet.ServletContainer.service(ServletContainer.java:229)
	org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)
	
SOLUTION: removed duplicate jar of bcprov...
<!-- javax.servlet.ServletException: org.glassfish.jersey.server.ContainerException: java.lang.NoClassDefFoundError: org/bouncycastle/jce/provider/BouncyCastleProvider -->
<dependency>
	<groupId>org.bouncycastle</groupId>
	<artifactId>bcprov-ext-jdk15on</artifactId> <!--  bcprov-jdk16[1.46] -->
	<version>1.58</version>
</dependency>
		 */
		ASN1EncodableVector attributes = new ASN1EncodableVector();

		SMIMESignedGenerator signer = new SMIMESignedGenerator();
		try {
			/*IssuerAndSerialNumber issAndSer = new IssuerAndSerialNumber(new X500Name(certDetails.getX509Certificate().getIssuerDN().getName()),
			certDetails.getX509Certificate().getSerialNumber());
	attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));*/
			
			attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
					SMIMEUtil.createIssuerAndSerialNumberFor(signerCertificate)));

			attributes.add(new SMIMECapabilitiesAttribute(capabilities));

			try {
				signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
						.setSignedAttributeGenerator(new AttributeTable(attributes))
						.build(signerCertificate.getSigAlgName(), signerPrivateKey, signerCertificate));

				List<X509Certificate> certList = Arrays.asList(signerCertificatesChain);
				Store certs;
				/** Add the list of certs to the generator */
				certs = new JcaCertStore(certList);
				signer.addCertificates(certs);
			} catch (CertificateEncodingException e) {
				log.error(e, e);
			} catch (OperatorCreationException e) {
				log.error(e, e);
			}
		} catch (CertificateParsingException e1) {
			log.error(e1, e1);
		}

		return signer;
	}

	
	
	private static final String MESSAGINGEXCEPTION_MESSAGE = "Allgemeine Nachrichtenverletzung. Bitte kontaktieren Sie Ihren Nachrichtensprecher";

	/**
	 * the socket factory to use if connecting with secure socket layer (SSL).
	 */
	private static final String SSLSOCKETFACTORY = "javax.net.ssl.SSLSocketFactory";
	/**
	 * Session properties.
	 * 
	 * @uml.property name="props"
	 * @uml.associationEnd qualifier="constant:java.lang.String
	 *                     java.lang.String"
	 */
	protected Properties props;

	/**
	 * Session for sending mail.
	 * 
	 * @uml.property name="session"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */
	protected Session session;

	/**
	 * the mail as MIME Message.
	 * 
	 * @uml.property name="message"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */
	protected MimeMessage message;

	/**
	 * the text part of the Mail.
	 * 
	 * @uml.property name="messageText"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */
	protected MimeBodyPart messageText;

	/**
	 * Attachment to the mail.
	 * 
	 * @uml.property name="attachmentMimeBody"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */

	/** private MimeBodyPart attachmentMimeBody; */

	/**
	 * configuration for this delivery.
	 * 
	 * @uml.property name="config"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */
	protected SMTP_Cong_XML config;

	/**
	 * the attachment to transmit.
	 * 
	 * @uml.property name="attachments"
	 * @uml.associationEnd multiplicity="(1 1)"
	 */
	protected List<AttachementFiles> attachments;

	protected List additionalRecipients;

	/**
	 * @uml.property name="recipientCertificate"
	 * @uml.associationEnd
	 */
	private X509Certificate recipientCertificate;

	/**
	 * @uml.property name="signerCertificate"
	 * @uml.associationEnd
	 */
	private X509Certificate signerCertificate;

	/**
	 * @uml.property name="signerCertificates"
	 * @uml.associationEnd multiplicity="(0 -1)"
	 */
	private X509Certificate[] signerCertificatesChain;

	/**
	 * @uml.property name="signerPrivateKey"
	 */
	private PrivateKey signerPrivateKey;

	public void setDeliverables(List attachments)
	{
		this.attachments = attachments;
	}

	public void addDeliverable(AttachementFiles attachment)
	{
		if (this.attachments == null)
		{
			attachments = new ArrayList<AttachementFiles>();
		}
		attachments.add(attachment);
	}

	public void clearDeliverables()
	{
		attachments.clear();
	}

	/**
	 * adds a recipient of the mail.
	 * 
	 * @param to
	 *            the recipient of the mail.
	 * @throws MailPreparingException
	 *             thrown if address is not syntactically correct.
	 */
	public void addRecipient(String to) throws MailPreparingException
	{

		if (additionalRecipients == null)
		{
			additionalRecipients = new ArrayList();
		}

		additionalRecipients.add(to);

	}
	
	protected void initializeSMIME()
	{

		CommandMap.getDefaultCommandMap();

		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

		mailcap.addMailcap(
				"application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		mailcap.addMailcap(
				"application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap.addMailcap(
				"application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap.addMailcap(
				"application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap.addMailcap(
				"multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

		CommandMap.setDefaultCommandMap(mailcap);

	}
	static Session mailSession;
	protected void initializeMessage() throws MailPreparingException
	{
		try {
			Properties props = new Properties();
			props.put("mail.smtp.host", (config.getRelayHost()));
			if (config.getRelayPort() != null)
			{
				props.put("mail.smtp.port", (config.getRelayPort()));
			}
			if (config.getRelayPort() != null)
			{
				props.put("mail.smtp.port", (config.getRelayPort()));
			}
			if (config.isSmtpAuth())
			{
				props.put("mail.smtp.auth", "true");
				props.put("mail.smtp.user", (config.getSmtpAuthLogin()));
				props.put("mail.smtp.password", (config.getSmtpAuthPassword()));
			}
			if (config.getDoSSL().booleanValue())
			{
				props.put("mail.smtp.socketFactory.class", SSLSOCKETFACTORY);
				props.put("mail.smtp.socketFactory.fallback", "false");
			}

			session = Session.getInstance(props);
			mailSession = session;
			
			message = new MimeMessage(session);

			if (!(config.getAdditionalHeaders() == null))
			{
				setAdditionalHeaders(config.getAdditionalHeaders());
			}

			if (config.getFrom() != null)
			{
				setFrom((config.getFrom()));
			}
			if (config.getTo() != null)
			{
				setTo((config.getTo()));
			}

			if (config.getCc() != null)
			{
				setCc((config.getCc()));
			}
			if (config.getBcc() != null)
			{
				setBcc((config.getBcc()));
			}
			if (config.getSubject() != null)
			{

				setSubject((config.getSubject()));
			}

			if (config.getBody() != null)
			{
				setBody((config.getBody()));
			}
		} catch (MailPreparingException e) {
			throw new MailPreparingException("Mailversand fehlgeschlagen: Probleme beim Ersetzen von Platzhaltern.", e);
		}

	}
	
	protected void setFrom(String from) throws MailPreparingException
	{
		try {
			message.setFrom(new InternetAddress(from));
			log.info("From::" + from + ":: " + Arrays.toString(message.getFrom()));
		} catch (AddressException e) {
			throw new MailPreparingException("", "Adresse im from:-Feld hat falsches Format: " + from, e);
		} catch (MessagingException e) {
			throw new MailPreparingException("", MESSAGINGEXCEPTION_MESSAGE, e);
		}
	}

	protected static List<String> formatMultipleMailIds(String mailIds)
	{
		List<String> mailLst = new ArrayList<String>();
		mailIds = mailIds.trim();
		String[] mailIdsArr = null;
		if (mailIds.contains(";"))
			mailIdsArr = mailIds.split(";");
		if (mailIdsArr != null)
			for (String mail : mailIdsArr)
				if (mail != null && !mail.trim().isEmpty())
					mailLst.add(mail.trim());
		return mailLst;
	}

	/**
	 * sets the recipient of the mail.
	 * 
	 * @param to
	 *            the recipient of the mail.
	 * @throws MailPreparingException
	 *             thrown if address is not syntactically correct.
	 */
	protected void setTo(String to) throws MailPreparingException
	{
		List<String> recipientArr = null;
		if (to != null && !to.trim().isEmpty())
		{
			to = to.trim();
			if (to.contains(";"))
				recipientArr = formatMultipleMailIds(to);
			else
			{
				recipientArr = new ArrayList<String>();
				recipientArr.add(to.trim());
			}
		}
		try {
			for (String recipientId : recipientArr)
			{
				if (recipientId != null && recipientId.trim().length() > 0)
					message.addRecipient(RecipientType.TO, new InternetAddress(recipientId));
			}
			log.info("to::" + to + "" + Arrays.toString(message.getAllRecipients()));
		} catch (AddressException e) {
			throw new MailPreparingException("", "Adresse im to:-Feld hat falsches Format: " + to, e);
		} catch (MessagingException e) {
			throw new MailPreparingException("", MESSAGINGEXCEPTION_MESSAGE, e);
		}
	}

	/**
	 * set the recipient of a carbon copy of this mail.
	 * 
	 * @param cc
	 *            the recipient of a carbon copy of this mail.
	 * @throws MailPreparingException
	 *             MailPreparingException thrown if address is not syntactically
	 *             correct.
	 */
	protected void setCc(String cc) throws MailPreparingException
	{
		List<String> recipientArr = null;
		if (cc != null && !cc.trim().isEmpty())
		{
			cc = cc.trim();
			if (cc.contains(";"))
				recipientArr = formatMultipleMailIds(cc);
			else
			{
				recipientArr = new ArrayList<String>();
				recipientArr.add(cc.trim());
			}
		}
		try {
			for (String recipientId : recipientArr)
			{
				if (recipientId != null && recipientId.trim().length() > 0)
					message.addRecipient(RecipientType.CC, new InternetAddress(recipientId));
			}

		} catch (AddressException e) {
			throw new MailPreparingException("", "Adresse im cc:-Feld hat falsches Format: " + cc, e);
		} catch (MessagingException e) {
			throw new MailPreparingException("", MESSAGINGEXCEPTION_MESSAGE, e);
		}
	}

	/**
	 * set the recipient of a blind carbon copy of this mail.
	 * 
	 * @param bcc
	 *            the recipient of a blind carbon copy of this mail.
	 * @throws MailPreparingException
	 *             MailPreparingException thrown if address is not syntactically
	 *             correct.
	 */
	protected void setBcc(String bcc) throws MailPreparingException
	{
		List<String> recipientArr = null;
		if (bcc != null && !bcc.trim().isEmpty())
		{
			bcc = bcc.trim();
			if (bcc.contains(";"))
				recipientArr = formatMultipleMailIds(bcc);
			else
			{
				recipientArr = new ArrayList<String>();
				recipientArr.add(bcc.trim());
			}
		}
		try {
			for (String recipientId : recipientArr)
			{
				if (recipientId != null && recipientId.trim().length() > 0)
					message.addRecipient(RecipientType.BCC, new InternetAddress(recipientId));
			}
		} catch (AddressException e) {
			throw new MailPreparingException("", "Adresse im bcc:-Feld hat falsches Format: " + bcc, e);
		} catch (MessagingException e) {
			throw new MailPreparingException("", MESSAGINGEXCEPTION_MESSAGE, e);
		}
	}

	/**
	 * set the subject for the mail.
	 * 
	 * @param subject
	 *            the subject for the mail
	 * @throws MailPreparingException
	 *             if subject contains invalid characters
	 * @see javax.mail.internet.MimeMessage#setSubject(java.lang.String)
	 */
	protected void setSubject(String subject) throws MailPreparingException
	{
		try {
			message.setSubject(subject);
			log.info("subject::" + subject + "" + message.getSubject());
		} catch (MessagingException e) {
			throw new MailPreparingException("", "Betreff der Mail fehlerhaft.", e);
		}
	}

	/**
	 * Adds the user defined headers to the mail.
	 * 
	 * @param headers
	 *            a Map consisitng of name-value pairs for custom headers.
	 * @throws MailPreparingException
	 * @throws MailPreparingException
	 */
	protected void setAdditionalHeaders(Map headers) throws MailPreparingException
	{
		try {
			for (Iterator it = headers.keySet().iterator(); it.hasNext();)
			{
				String key = (String) (it.next());

				message.addHeader((key), ((String) (headers.get(key))));
				log.info("headerss:" + message.getHeader(key));
			}
		} catch (MessagingException e) {
			throw new MailPreparingException("", "Header der Mail fehlerhaft!", e);
		}
	}

	/**
	 * the message text for the body.
	 * 
	 * @param body
	 *            message text.
	 * @throws MailPreparingException
	 */
	protected void setBody(String body) throws MailPreparingException
	{
		messageText = new MimeBodyPart();
		try {

			messageText.setText(body);
			/**
			 * messageBodyPart.setHeader("Content-Type", "text/plain;
			 * charset=\"us-ascii\"; name=\"mail.txt\"");
			 */
			log.info("MessgaeTest::" + body);
		} catch (MessagingException e) {
			throw new MailPreparingException("", "Text der Mail fehlerhaft!", e);
		}
	}
}


