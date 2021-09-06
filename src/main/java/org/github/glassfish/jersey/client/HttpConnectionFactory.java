package org.github.glassfish.jersey.client;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.glassfish.hk2.utilities.reflection.Logger;

public class HttpConnectionFactory {
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
		
		org.apache.http.config.Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
				.register("http", org.apache.http.conn.socket.PlainConnectionSocketFactory.getSocketFactory())
				.register("https", org.apache.http.conn.ssl.SSLConnectionSocketFactory.getSystemSocketFactory())
				.build();
		PoolingHttpClientConnectionManager cm = new org.apache.http.impl.conn.PoolingHttpClientConnectionManager(socketFactoryRegistry);
		config.property(org.glassfish.jersey.apache.connector.ApacheClientProperties.CONNECTION_MANAGER, cm);
		
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
