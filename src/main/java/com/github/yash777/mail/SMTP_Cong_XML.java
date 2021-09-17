package com.github.yash777.mail;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/*
<deliveryconfig>
<moduleId name="SMTP" />
<smtpconfig>
  <data-content>
    <from></from>
    <to></to>
    <subject>Test Mail</subject>
    <body />
  </data-content>
  <deliverypath>
    <relay host="" port="25" />
  </deliverypath>
  <security>
    <sign signerKey="Baeldung.p12" signerKeyPassword="password" />
    <signModeDetached>true</signModeDetached>  
	<encrypt recipientCert="Baeldung.cer"/>
  </security>
</smtpconfig>
</deliveryconfig> */
public class SMTP_Cong_XML {
	private static final String XML_PREFIX = "/deliveryconfig/smtpconfig";
	private static Set<String> mandatoryFields = new HashSet<String>();

	static {
		mandatoryFields.add("from");
		// mandatoryFields.add("to");
		mandatoryFields.add("relayHost");
	}
	
	private boolean encryptionHash = false;
	public boolean isEncryptionHash() {
		return encryptionHash;
	}
	public void setEncryptionHash(boolean encryptionHash) {
		this.encryptionHash = encryptionHash;
	}

	private String from, to, cc, bcc;
	private String subject;
	private String body;
	private String relayHost, relayPort;
	private String smtpAuthLogin, smtpAuthPassword;

	private Boolean doSSL, signed, signModeDetached, doEncrypt, deliveryReceipt;

	private String recipientCertificate;
	private String signerKey, signerKeyPassword;

	private Map<String, String> additionalHeaders;

	@Override
	public String toString() {
		return "SMTP_Cong_XML [from=" + from + ", to=" + to + ", cc=" + cc + ", bcc=" + bcc + ", subject=" + subject
				+ ", body=" + body + ", relayHost=" + relayHost + ", relayPort=" + relayPort + ", smtpAuthLogin="
				+ smtpAuthLogin + ", smtpAuthPassword=" + smtpAuthPassword + ", doSSL=" + doSSL + ", signed=" + signed
				+ ", signModeDetached=" + signModeDetached + ", doEncrypt=" + doEncrypt + ", deliveryReceipt="
				+ deliveryReceipt + ", recipientCertificate=" + recipientCertificate + ", signerKey=" + signerKey
				+ ", signerKeyPassword=" + signerKeyPassword + ", additionalHeaders=" + additionalHeaders + ", encryptionHash="+encryptionHash+ "]";
	}
	
	public boolean isSmtpAuth() {
		return ((smtpAuthLogin != null) && (smtpAuthPassword != null));
	}
	
	public SMTP_Cong_XML(Document doc) throws Exception {
		readFromXml(doc, XML_PREFIX);
	}
	
	
	public void readFromXml(Document doc, String xmlPath) throws Exception {
		try {
			setFrom(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/from/text()", mandatoryFields.contains("from")));
			setTo(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/to/text()", mandatoryFields.contains("to")));
			setCc(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/cc/text()", mandatoryFields.contains("cc")));
			setBcc(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/bcc/text()", mandatoryFields.contains("bcc")));
			setSubject(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/subject/text()", mandatoryFields.contains("subject")));
			setRelayHost(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/deliverypath/relay/@host", mandatoryFields.contains("relayHost")));
			setRelayPort(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/deliverypath/relay/@port", mandatoryFields.contains("relayPort")));
			setBody(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/data-content/body/text()", mandatoryFields.contains("body")));
			setSmtpAuthLogin(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/security/smtp-auth/@login", mandatoryFields.contains("smtpAuthLogin")));
			setSmtpAuthPassword(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/security/smtp-auth/@password", mandatoryFields.contains("smtpAuthPassword")));
			setDoSSL(new Boolean((XMLHelperFinal.getNode(doc, xmlPath + "/security/ssl") != null)));
			setSigned(new Boolean((XMLHelperFinal.getNode(doc, xmlPath + "/security/sign") != null)));
			setSignModeDetached(new Boolean((XMLHelperFinal.getNode(doc, xmlPath+ "/security/signModeDetached") != null)));
			setDoEncrypt(new Boolean((XMLHelperFinal.getNode(doc, xmlPath + "/security/encrypt") != null)));
			setDeliveryReceipt(new Boolean((XMLHelperFinal.getNode(doc, xmlPath + "/delivery-receipt") != null)));
			setRecipientCertificate(XMLHelperFinal.getNodeAsString(doc,xmlPath + "/security/encrypt/@recipientCert",mandatoryFields.contains("recipientCertificate")));
			setSignerKey(XMLHelperFinal.getNodeAsString(doc,xmlPath + "/security/sign/@signerKey", mandatoryFields.contains("signerKey")));
			setSignerKeyPassword(XMLHelperFinal.getNodeAsString(doc, xmlPath + "/security/sign/@signerKeyPassword", mandatoryFields.contains("signerKeyPassword")));

			setAdditionalHeaders(new HashMap<String, String>());
			NodeList nl = XMLHelperFinal.getNodeList(doc, xmlPath + "/data-content/additionalHeaders/header", mandatoryFields.contains("additionalHeaders"));
			for (int i = 0; i < nl.getLength(); i++) {
				Node n = nl.item(i);
				String key = XMLHelperFinal.getNodeAsString(n, "@name", mandatoryFields.contains("additionalHeaders"));
				String value = XMLHelperFinal.getNodeAsString(n, "@value", mandatoryFields.contains("additionalHeaders"));
				
				if ((key != null) && (value != null)) {
					getAdditionalHeaders().put(key, value);
				} else {
					throw new Exception("Header-Daten in der Konfiguration nicht konsistent!");
				}
			}
			
			setEncryptionHash(new Boolean((XMLHelperFinal.getNode(doc, xmlPath+ "/encryptionHash") != null)));
		} catch (Exception e) {
			throw new Exception("", e);
		}
	}
	
	public static Set<String> getMandatoryFields() {
		return mandatoryFields;
	}

	public static void setMandatoryFields(Set<String> mandatoryFields) {
		SMTP_Cong_XML.mandatoryFields = mandatoryFields;
	}

	public String getFrom() {
		return from;
	}

	public void setFrom(String from) {
		this.from = from;
	}

	public String getTo() {
		return to;
	}

	public void setTo(String to) {
		this.to = to;
	}

	public String getCc() {
		return cc;
	}

	public void setCc(String cc) {
		this.cc = cc;
	}

	public String getBcc() {
		return bcc;
	}

	public void setBcc(String bcc) {
		this.bcc = bcc;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}

	public String getRelayHost() {
		return relayHost;
	}

	public void setRelayHost(String relayHost) {
		this.relayHost = relayHost;
	}

	public String getRelayPort() {
		return relayPort;
	}

	public void setRelayPort(String relayPort) {
		this.relayPort = relayPort;
	}

	public String getSmtpAuthLogin() {
		return smtpAuthLogin;
	}

	public void setSmtpAuthLogin(String smtpAuthLogin) {
		this.smtpAuthLogin = smtpAuthLogin;
	}

	public String getSmtpAuthPassword() {
		return smtpAuthPassword;
	}

	public void setSmtpAuthPassword(String smtpAuthPassword) {
		this.smtpAuthPassword = smtpAuthPassword;
	}

	public Boolean getDoSSL() {
		return doSSL;
	}

	public void setDoSSL(Boolean doSSL) {
		this.doSSL = doSSL;
	}

	public Boolean getSigned() {
		return signed;
	}

	public void setSigned(Boolean signed) {
		this.signed = signed;
	}

	public Boolean getSignModeDetached() {
		return signModeDetached;
	}

	public void setSignModeDetached(Boolean signModeDetached) {
		this.signModeDetached = signModeDetached;
	}

	public Boolean getDoEncrypt() {
		return doEncrypt;
	}

	public void setDoEncrypt(Boolean doEncrypt) {
		this.doEncrypt = doEncrypt;
	}

	public Boolean getDeliveryReceipt() {
		return deliveryReceipt;
	}

	public void setDeliveryReceipt(Boolean deliveryReceipt) {
		this.deliveryReceipt = deliveryReceipt;
	}

	public String getRecipientCertificate() {
		return recipientCertificate;
	}

	public void setRecipientCertificate(String recipientCertificate) {
		this.recipientCertificate = recipientCertificate;
	}

	public String getSignerKey() {
		return signerKey;
	}

	public void setSignerKey(String signerKey) {
		this.signerKey = signerKey;
	}

	public String getSignerKeyPassword() {
		return signerKeyPassword;
	}

	public void setSignerKeyPassword(String signerKeyPassword) {
		this.signerKeyPassword = signerKeyPassword;
	}

	public Map<String, String> getAdditionalHeaders() {
		return additionalHeaders;
	}

	public void setAdditionalHeaders(Map<String, String> additionalHeaders) {
		this.additionalHeaders = additionalHeaders;
	}
	
	public boolean isDeliveryReceipt() {
		return deliveryReceipt;
	}
}