package com.github.yash777.mail;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.Certificate;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html


public class CertsUtil {
	// NoSuchProviderException: no such provider: BC
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	static boolean onlyValues = true;
	static FileOpreations fileObj = new FileOpreations();
	
	static String security_privatekey = "Baeldung.p12", password="password";
	static String security_certificate = "Baeldung.cer";
	
	private static String getThumbprintPrvt(PrivateKey privateKey, String algorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm); // "SHA-1", MD5, SHA, MD2, MD5, SHA-256, SHA-384...
        byte[] der = privateKey.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        
        return insertEveryNCharacters(digestHex.toUpperCase(), ":", 2);
    }
	
	private static final Pattern KEY_TYPE_PATTERN = Pattern.compile("^(\\w+)[.].*$");
    private static final Pattern KEY_ALIAS_TYPE_PATTERN = Pattern.compile("^Alg[.]Alias[.](\\w+).*$");
    private static final Pattern KEY_OID_PATTERN = Pattern.compile(".*?(\\d+(?:[.]\\d+){3,})$");
	public static void getOIDToAlgorithmNameMapping() {
    	try {
    		java.security.Provider[] provs = Security.getProviders();

            for (java.security.Provider prov : provs) {
                System.out.printf("%n >>> Provider: %s <<< %n%n", prov.getName());

                SortedSet<String> typeAndOID = getTypeAndOIDStrings(prov);

                for (String entry : typeAndOID) {
                    String[] typeAndOIDArray = entry.split("-");
                    String type = typeAndOIDArray[0];
                    String oid = typeAndOIDArray[1];
                    Service service = prov.getService(type, oid);
                    String algo = service.getAlgorithm();
                    System.out.printf("Type: %s, OID: %s, algo: %s%n", type, oid, algo);
                }
            }
    	} catch (Exception e) {
    		
    	}
    }

	public static X509Certificate getX509Cert(String security_certificate) throws CertificateException, NoSuchProviderException, FileNotFoundException {
		InputStream cerFileStream = fileObj.getCerFileStream(true, security_certificate);
		X509Certificate loadPublicKeyX509 = loadPublicKeyX509(cerFileStream);
		//System.out.println("loadPublicKeyX509 : "+ loadPublicKeyX509);
		
		return loadPublicKeyX509;
	}
	public static PublicKey getPublicCert(String security_certificate) throws CertificateException, NoSuchProviderException, FileNotFoundException {
		InputStream cerFileStream = fileObj.getCerFileStream(true, security_certificate);
		X509Certificate loadPublicKeyX509 = loadPublicKeyX509(cerFileStream);
		//System.out.println("loadPublicKeyX509 : "+ loadPublicKeyX509);
		
		PublicKey publicKey = loadPublicKeyX509.getPublicKey();
		System.out.println("loadPublicKey : "+ publicKey);
		return publicKey;
	}
	
    private static SortedSet<String> getTypeAndOIDStrings(java.security.Provider prov) {
        SortedSet<String> typeAndOID = new TreeSet<String>();

        Set<Object> keys = prov.keySet();
        for (Object key : keys) {
            String keyString = key.toString();
            Matcher oidMatcher = KEY_OID_PATTERN.matcher(keyString);
            if (oidMatcher.matches()) {
                // get OID from matched keyString
                String oid = oidMatcher.group(1);

                // determine type
                String type;
                Matcher aliasTypeMatcher = KEY_ALIAS_TYPE_PATTERN.matcher(keyString);
                if (aliasTypeMatcher.matches()) {
                    type = aliasTypeMatcher.group(1);
                } else {
                    Matcher typeMatcher = KEY_TYPE_PATTERN.matcher(keyString);
                    typeMatcher.matches();
                    type = typeMatcher.group(1);
                }

                // algorithm parameters are not algorithms, so skip them
                if (type.equals("AlgorithmParameters")) {
                    continue;
                }

                // auto-removes dupes
                typeAndOID.add(type + "-" + oid);
            }
        }
        return typeAndOID;
    }
    
    public static void listPrivateKeyDetails(String privateKeyFile, String password) throws Exception {
    	System.out.println("===== PrivateKeyDetails =====");
    	InputStream pkcs_FileStream = fileObj.getCerFileStream(true, privateKeyFile);
		System.out.println("cerFileStream : "+pkcs_FileStream); 
		
		PrivateKey privateKey = loadPrivateKeyforSigning(pkcs_FileStream, password);
		System.out.println("privateKey : "+privateKey);
		
		String algorithm = privateKey.getAlgorithm();
		System.out.println("Sender - signature algorithm :"+algorithm);
		
		String format = privateKey.getFormat();
		System.out.println("format : "+format);
		
		RSAPrivateKey rprvt = (RSAPrivateKey) privateKey;
		System.out.println("Algorithm: " + rprvt.getAlgorithm());
		System.out.println("bitLength: " + rprvt.getModulus().bitLength());
		
		System.out.println("getEncoded: " + rprvt.getEncoded());
		System.out.println("Fingerprint SHA1 : "+ getThumbprintPrvt(rprvt, "SHA-1") );
		System.out.println("Fingerprint SHA256 : "+ getThumbprintPrvt(rprvt, "SHA-256") );
		System.out.println("Fingerprint MD5 : "+ getThumbprintPrvt(rprvt, "MD5") );
		
		BigInteger privateExponent = (rprvt).getPrivateExponent();
		System.out.println("privateExponent DEC : "+privateExponent);
		
		String hex = privateExponent.toString(16).toUpperCase();
		System.out.println("Serial Number HEX : "+ hex);
    }
    
    public static void listPublicKeyDetails(String publicKeyFile) throws Exception {
    	System.out.println("===== PublicKeyDetails ===== :"+publicKeyFile);
		InputStream cerFileStream = fileObj.getCerFileStream(true, publicKeyFile);
		X509Certificate loadPublicKeyX509 = loadPublicKeyX509(cerFileStream);
		//System.out.println("loadPublicKeyX509 : "+ loadPublicKeyX509);
		
		PublicKey publicKey = loadPublicKeyX509.getPublicKey();
		System.out.println("loadPublicKey : "+ publicKey);
		
		RSAPublicKey rsaPk = (RSAPublicKey) loadPublicKeyX509.getPublicKey();
		System.out.println("Len: " + rsaPk.getAlgorithm());
		System.out.println("Len: " + rsaPk.getModulus().bitLength());
		
		System.out.println("signature algorithm : "+ loadPublicKeyX509.getSigAlgName() ); // Alg:RSA, SigAlg:SHA256withRSAandMGF1
		System.out.println("signature algorithm : "+ loadPublicKeyX509.getSigAlgOID() ); // SigAlgOID: 1.2.840.113549.1.1.1
		System.out.println("Type : "+ loadPublicKeyX509.getType() ); // X.509
		
		String str = "";
		byte[] sigAlgParams = loadPublicKeyX509.getSigAlgParams();
		for (int i = 0; i < sigAlgParams.length; i++) {
			str += sigAlgParams[i];
		}
		System.out.println("DER-encoded signature : "+ str);
		
		Set<String> criticalExtensionOIDs = loadPublicKeyX509.getCriticalExtensionOIDs();
		System.out.println("criticalExtensionOIDs : "+criticalExtensionOIDs);
		
		Set<String> nonCriticalExtensionOIDs = loadPublicKeyX509.getNonCriticalExtensionOIDs();
		System.out.println("nonCriticalExtensionOIDs : "+nonCriticalExtensionOIDs);
		
		Collection<List<?>> issuerAlternativeNames = loadPublicKeyX509.getIssuerAlternativeNames();
		System.out.println("issuerAlternativeNames :"+issuerAlternativeNames);
		
		X500Principal issuerX500Principal = loadPublicKeyX509.getIssuerX500Principal();
		System.out.println("issuerX500Principal :"+issuerX500Principal);
		
		getCertificateDetails(loadPublicKeyX509, publicKeyFile);
    }
    
	public static void main(String[] args) throws Exception {
		//getOIDToAlgorithmNameMapping();
		
		//listPrivateKeyDetails(security_privatekey, password);
		listPublicKeyDetails(security_certificate);
		
		/*// https://stackoverflow.com/a/35126881/5081877
		String KeyUsages = "";
		boolean[] keyUsage2 = rprvt.getKeyUsage();
		String[] keys = {"Digital-Signature", "Non-Repudiation", "key-Encipherment", "Data-Encipherment", "Key-Agreement"
				,"Key-CertSign", "CRL-Sign", "EncipherOnly", "DecipherOnly"};
		
		for (int i = 0; (keyUsage2.length == keys.length) && i < keyUsage2.length; i++) {
			//System.out.println("keyUsage2 : "+keyUsage2[i]);
			if (keyUsage2[i]) {
				if (KeyUsages.length() > 0) {
					KeyUsages += ", ";
				}
				KeyUsages += keys[i];
			}
		}*/
		
		//getCertificateDetailsPrvt(privateKey);
		
		/*String SYMMETRIC_KEY_ALG = "AES";
		// generate random AES key
		 KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_ALG);
		 SecretKey symmetricKey = keyGenerator.generateKey();

		 // this assumes there's whole keypair (including private key)
		 // normally only a certificate with PubKey is available
		// PublicKey pubKey = keystoreEntry.getCertificate().getPublicKey();

		 SecretKeySpec secretKey = new SecretKeySpec(publicKey.getEncoded(), algorithm);
		 
		 //params.setKey(symmetricKey.getEncoded());
		 // execute symmetric encryption
		 //this.symmetricEncryption(params);
		 // encrypt the key with the public key
		 Cipher cipher = Cipher.getInstance(algorithm);
		 cipher.init(Cipher.WRAP_MODE, publicKey);
		 byte[] wrappedKey = cipher.wrap(symmetricKey);
		System.out.println(".. "+ Base64.getEncoder().encodeToString(wrappedKey));
		 //params.setKey(wrappedKey);
*/	}
	
	public static String getCRL_DistPoint(byte[] bytes) throws IOException {
		//byte[] bytes = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(bytes));
        DEROctetString derObjCrlDP = (DEROctetString) oAsnInStream.readObject();
        DEROctetString dosCrlDP = derObjCrlDP;

        oAsnInStream.close();

        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = (ASN1Primitive) oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

        oAsnInStream2.close();

        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
        }

        String urls = "";
        for (String url : crlUrls) {
        	System.out.println(url);
        	urls += url;
        }
        return urls;
	}
	
	private static String getThumbprint(X509Certificate cert, String algorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm); // "SHA-1", MD5, SHA, MD2, MD5, SHA-256, SHA-384...
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        
        return insertEveryNCharacters(digestHex.toUpperCase(), ":", 2);
    }
	
	public static String isValid (X509Certificate cert) {
        try {
            cert.checkValidity ();
            return "The certificate is still valid [true]";
        } catch ( final Exception e ) {
        }
	    return "The certificate is not valid [false]";
	}
	
	public static void testConnectionTo(String aURL) throws Exception {
        URL destinationURL = new URL(aURL);
        URLConnection conn = null;
        if (aURL.startsWith("https:")) {
        	HttpsURLConnection con = (HttpsURLConnection) destinationURL.openConnection();
        	conn = con;
        } else if (aURL.startsWith("http:")) {
        	HttpURLConnection con = (HttpURLConnection) destinationURL.openConnection();
        	conn = con;
        }
        
        if(conn!=null){
	        try {
		
		      	System.out.println("Response Code : " + ((HttpURLConnection) conn).getResponseCode());
		      	System.out.println("Cipher Suite : " + ((HttpsURLConnection) conn).getCipherSuite());
		      	System.out.println("\n");
		
		      	Certificate[] certs = (Certificate[]) ((HttpsURLConnection) conn).getServerCertificates();
		      	for(Certificate cert : certs){
		      	   System.out.println("Cert Type : " + ((KeyStore) cert).getType());
		      	   System.out.println("Cert Hash Code : " + cert.hashCode());
		      	   System.out.println("Cert Public Key Algorithm : " + cert.getPublicKey().getAlgorithm());
		      	   System.out.println("Cert Public Key Format : " + cert.getPublicKey().getFormat());
		      	   System.out.println("\n");
		      	   
		      	   System.out.println("Certificate is: " + cert);
		           if(cert instanceof X509Certificate) {
		                try {
		                    ( (X509Certificate) cert).checkValidity();
		                    System.out.println("Certificate is active for current date");
		                } catch(CertificateExpiredException cee) {
		                    System.out.println("Certificate is expired");
		                }
		            }
		      	}
	
	      	} catch (SSLPeerUnverifiedException e) {
	      		e.printStackTrace();
	      	} catch (IOException e){
	      		e.printStackTrace();
	      	}
           }
        
    }
	
	public static HashMap<String, String> getCertificateDetails(X509Certificate loadPublicKeyX509, String certFileName) throws CertificateEncodingException, NoSuchAlgorithmException, CertificateParsingException, IOException, Exception {
		HashMap<String, String> certInfo_Value  = new LinkedHashMap<String, String>();
		certInfo_Value.put("Certificate", "Name:"+certFileName );
		System.out.println("===== getCertificateDetails() =====");
		// EMAILADDRESS=fpmtest@50hertz.com, CN=Dominik Wagner, OU=MSP-T, O=50Hertz Transmission GmbH, L=Berlin, ST=Berlin, C=DE
		// C=DE,ST=Berlin,L=Berlin,O=50Hertz Transmission GmbH,OU=MSP-T,CN=Dominik Wagner,E=fpmtest@50hertz.com
		Principal subjectDN = loadPublicKeyX509.getSubjectDN();
		System.out.println("Owner SubjectDN :"+subjectDN); // EMAILADDRESS
		certInfo_Value.put("Owner (Subject)", subjectDN.toString().replace("E=", "EMAILADDRESS=") );
		
		int version = loadPublicKeyX509.getVersion();
		certInfo_Value.put("Version", "V"+version );
		
		Principal issuerDN = loadPublicKeyX509.getIssuerDN();
		System.out.println("Issued By IssuerDN :"+issuerDN);
		certInfo_Value.put("Issued By", issuerDN.toString() );
		
		Date notAfter = loadPublicKeyX509.getNotAfter();
		System.out.println("notAfter : "+notAfter);
		
		Date notBefore = loadPublicKeyX509.getNotBefore();
		System.out.println("notBefore : "+notBefore);
		
		certInfo_Value.put("Valid From", notBefore.toString() );
		certInfo_Value.put("Valid Until", notAfter.toString() );
		// https://www.programcreek.com/java-api-examples/?class=java.security.cert.X509Certificate&method=checkValidity
		certInfo_Value.put("Time Expired Check (Validity)", isValid(loadPublicKeyX509) );
		
		
		// https://stackoverflow.com/a/32573561/5081877
		RSAPublicKey rsaPk = (RSAPublicKey) loadPublicKeyX509.getPublicKey();
		String algorithm = rsaPk.getAlgorithm();
		
		// https://docs.oracle.com/en/java/javase/12/docs/specs/security/standard-names.html
		if (algorithm.equals("RSA")) {
			algorithm = "RSA algorithm (Signature/Cipher)";
		}
		System.out.println("Algorithm: " + algorithm);
		System.out.println("bitLength: " + rsaPk.getModulus().bitLength());
		
		// 
		certInfo_Value.put("Key Length (Public Key)", algorithm + " (" + rsaPk.getModulus().bitLength()+" bits)");
		
		/*List<String> extendedKeyUsage = loadPublicKeyX509.getExtendedKeyUsage();
		String KeyUsages = ""; // 1.3.6.1.5.5.7.3.2 | 1.3.6.1.5.5.7.3.4 | [T, F, T, FFF]
		for (String keys : extendedKeyUsage) {
			KeyUsages += keys +" | ";
		}*/
		
		// https://stackoverflow.com/a/35126881/5081877
		String KeyUsages = "";
		boolean[] keyUsage2 = loadPublicKeyX509.getKeyUsage();
		String[] keys = {"Digital-Signature", "Non-Repudiation", "key-Encipherment", "Data-Encipherment", "Key-Agreement"
				,"Key-CertSign", "CRL-Sign", "EncipherOnly", "DecipherOnly"};
		
		for (int i = 0; (keyUsage2.length == keys.length) && i < keyUsage2.length; i++) {
			//System.out.println("keyUsage2 : "+keyUsage2[i]);
			if (keyUsage2[i]) {
				if (KeyUsages.length() > 0) {
					KeyUsages += ", ";
				}
				KeyUsages += keys[i];
			}
		}
		certInfo_Value.put("Key Usage", KeyUsages); // (e.g., encipherment, signature, certificate signing)
		
		String sigAlgName = loadPublicKeyX509.getSigAlgName();
		System.out.println("Signature Algorithm : "+sigAlgName); // SHA256withRSAandMGF1
		String sigAlgOID = loadPublicKeyX509.getSigAlgOID();
		System.out.println("Signature Algorithm ODI : "+sigAlgOID); // 1.2.840.113549.1.1.10
		/*byte[] sigAlgParams = loadPublicKeyX509.getSigAlgParams();
		for (int i = 0; i < sigAlgParams.length; i++) {
			System.out.println("sigAlgParams :"+sigAlgParams[i]);
		}*/
		
		// https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509signatureinformation-get_parameters
		// https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionsmimecapabilities
		HashMap<String, String> SignAlog = new HashMap<String, String>();
		SignAlog.put("1.2.840.113549.1.1.10", "RSASSA-PSS"); // RSASSA-PSS algorithm (Signature)
		SignAlog.put("1.2.840.113549.1.1.1", "RSA_SIGN");
		SignAlog.put("1.2.840.113549.1.1.2", "RSA_MD2RSA");
		SignAlog.put("1.2.840.113549.1.1.4", "RSA_MD5RSA");
		SignAlog.put("1.2.840.113549.1.1.5", "RSA_SHA1RSA");
		SignAlog.put("1.2.840.113549.1.1.11", "RSA_SHA256RSA");
		SignAlog.put("1.2.840.113549.1.1.12", "RSA_SHA384RSA");
		SignAlog.put("1.2.840.113549.1.1.13", "RSA_SHA512RSA");
		
		//org.apache.commons.lang.ArrayUtils.reverse(encryptedSessionKey);
		
		String xcn_sigAlgName = "";
		if (SignAlog.containsKey(sigAlgOID)) {
			xcn_sigAlgName = SignAlog.get(sigAlgOID);
		} else {
			xcn_sigAlgName = sigAlgOID;
		}
		
		/*Signature Algorithm: SHA1withRSA,        OID = 1.2.840.113549.1.1.5
		Signature Algorithm: SHA2withRSA,          OID = 1.2.840.113549.1.1.11
		Signature Algorithm: SHA256withRSAandMGF1, OID = 1.2.840.113549.1.1.10*/
		certInfo_Value.put("Encoding Format", rsaPk.getFormat() );
		certInfo_Value.put("Signature Algorithm", algorithm + " (Algorithm-ODI:"+xcn_sigAlgName+")");
		certInfo_Value.put("Signature Algorithm ObjectId", sigAlgOID );
		certInfo_Value.put("Signature Hash Algorithm", sigAlgName );
		
		
		// https://stackoverflow.com/a/12583135/5081877
		BigInteger serialNumber = loadPublicKeyX509.getSerialNumber();
		String hex = serialNumber.toString(16).toUpperCase();
		String dec = serialNumber.toString();
		System.out.println("Serial Number Dec : "+ dec);
		System.out.println("Serial Number Hex : "+ insertEveryNCharacters(hex, ":", 2) ); // https://stackoverflow.com/a/48951256/5081877
		
		// https://stackoverflow.com/a/1271148/5081877
		System.out.println("Fingerprint SHA1 : "+ getThumbprint(loadPublicKeyX509, "SHA-1") );
		System.out.println("Fingerprint SHA256 : "+ getThumbprint(loadPublicKeyX509, "SHA-256") );
		System.out.println("Fingerprint MD5 : "+ getThumbprint(loadPublicKeyX509, "MD5") );
		
//		certInfo_Value.put("Serial Number Dec", dec );
//		certInfo_Value.put("Serial Number Hex", insertEveryNCharacters(hex, ":", 2) );
//		certInfo_Value.put("Fingerprint SHA1", getThumbprint(loadPublicKeyX509, "SHA-1") );
//		certInfo_Value.put("Fingerprint SHA256", getThumbprint(loadPublicKeyX509, "SHA-256") );
//		certInfo_Value.put("Fingerprint MD5",  getThumbprint(loadPublicKeyX509, "MD5") );
		
		String mailAddress = "";
		try {
			Collection<List<?>> subjectAlternativeNames = loadPublicKeyX509.getSubjectAlternativeNames();
			for (List<?> list : subjectAlternativeNames) {
				for (Object object : list) {
					if (object instanceof String && ((String) object).contains("@")) {
						mailAddress += (String) object;
					}
				}
				System.out.println("list : "+list); // [1, fpmtest@50hertz.com]
			}
		} catch (Exception e) {
			System.out.println("Error: "+e.getMessage());
		}
//		certInfo_Value.put("Subject Alternative Name with E-Mail", mailAddress );
		certInfo_Value.put("E-Mail", mailAddress );
		String crl_DistPoint = null, ocspUrlFromCertificate= null;
		try {
			// https://stackoverflow.com/a/47417951/5081877
			byte[] bytesCRL = loadPublicKeyX509.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
			crl_DistPoint = getCRL_DistPoint(bytesCRL);
			
			// https://stackoverflow.com/a/40268997/5081877
			ocspUrlFromCertificate = getOcspUrlFromCertificate(loadPublicKeyX509);
			
		} catch (Exception e) {
			System.out.println("Error: "+e.getMessage());
		}
		certInfo_Value.put("CRL DistPoint", crl_DistPoint );
		certInfo_Value.put("OCSP URL", ocspUrlFromCertificate );
		
		if (crl_DistPoint != null) {
			certInfo_Value.put("Self Signed Check", "Certificate is not self signed" );
		} else {
			certInfo_Value.put("Self Signed Check", "Certificate is self signed" );
		}
		//https://stackoverflow.com/questions/7199129/how-to-get-server-certificate-chain-then-verify-its-valid-and-trusted-in-java
		//testConnectionTo(crl_DistPoint);
		
		/*System.setProperty("com.sun.net.ssl.checkRevocation", "true");
		Security.setProperty("ocsp.enable", "true");
		// Fallback check for CRL if no OCSP is available
		System.setProperty("com.sun.security.enableCRLDP", "true");
		PKIXParameters params = �;
		params.setRevocationEnabled(true);
		// Fallback check for CRL if no OCSP is available
		CertPathValidator validator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
		validator.validate(certificatePath, params);*/
		
		
		
		//VerifyCertificateCAs.verifyCertificateCRLs(loadPublicKeyX509);
		
		System.out.println("Cert: "+certInfo_Value);
		
		System.out.println("===== ----- =====");
		Set<String> keySet = certInfo_Value.keySet();
		for (String key : keySet) {
			if (onlyValues) {
				System.out.format("%s\n", certInfo_Value.get(key));
			} else {
				System.out.format("%-30s : %s\n", key, certInfo_Value.get(key));
			}
		}
		return certInfo_Value;
	}
	
	private static String getOcspUrlFromCertificate(X509Certificate cert) {
	    byte[] extensionValue = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());

	    try {
	        ASN1Sequence asn1Seq = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(extensionValue); // AuthorityInfoAccessSyntax
	        Enumeration<?> objects = asn1Seq.getObjects();

	        while (objects.hasMoreElements()) {
	            ASN1Sequence obj = (ASN1Sequence) objects.nextElement(); // AccessDescription
	            ASN1Encodable objectAt = (ASN1Encodable) obj.getObjectAt(0);
	            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) objectAt; // accessMethod
	            DERTaggedObject location = (DERTaggedObject) obj.getObjectAt(1); // accessLocation

	            if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
	                DEROctetString uri = (DEROctetString) location.getObject();
	                String str = new String(uri.getOctets());
	                if (oid.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
	                	System.out.println("OCSP URL :"+str);
	                    return str;
	                }
	            }
	        }
	    } catch (Exception e) {
	        System.out.println("Error :"+ e);
	    }

	    return null;
	}
	
	private static String insertEveryNCharacters(String originalText, String textToInsert, int breakInterval) {
	    String withBreaks = "";
	    int textLength = originalText.length(); //initialize this here or in the start of the for in order to evaluate this once, not every loop
	    for (int i = breakInterval , current = 0; i <= textLength || current < textLength; current = i, i += breakInterval ) {
	        if(current != 0) {  //do not insert the text on the first loop
	            withBreaks += textToInsert;
	        }
	        if(i <= textLength) { //double check that text is at least long enough to go to index i without out of bounds exception
	            withBreaks += originalText.substring(current, i);
	        } else { //text left is not longer than the break interval, so go simply from current to end.
	            withBreaks += originalText.substring(current); //current to end (if text is not perfectly divisible by interval, it will still get included)
	        }
	    }
	    return withBreaks;
	}
	
	public static X509Certificate loadPublicKeyX509(InputStream cerFileStream) throws CertificateException, NoSuchProviderException {
		/*KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
		keyStore.load(cerFileStream, "changeit");
		Certificate certificate = (Certificate) keyStore.getCertificate("receiverKeyPair");
		PublicKey publicKey = certificate.getPublicKey();*/
		CertificateFactory	certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(cerFileStream);
		return x509Certificate;
	}
	
	public static X509Certificate loadPrivateKeyforSigningCert(InputStream cerFileStream, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
			
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certPvt = (X509Certificate) certificateFactory.generateCertificate(cerFileStream);
		
		//PrivateKey privateKey = (PrivateKey) keyStore.getKey("senderKeyPair", password.toCharArray());
		return certPvt;
	}
	
	
	public static PrivateKey loadPrivateKeyforSigning(InputStream cerFileStream, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12"); //, "BC");
		keyStore.load(cerFileStream, password.toCharArray());
		
		Enumeration<String> keyStoreAliasEnum = keyStore.aliases();
		PrivateKey privateKey = null;
		String alias = null;
		if (keyStoreAliasEnum.hasMoreElements())
		{
			alias = keyStoreAliasEnum.nextElement();
			if (password != null)
			{
				privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			}
		}
		
		//PrivateKey privateKey = (PrivateKey) keyStore.getKey("senderKeyPair", password.toCharArray());
		return privateKey;
	}
	
	
}
