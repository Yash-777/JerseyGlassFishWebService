package com.github.yash777.mail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.pdfbox.io.IOUtils;
//import org.apache.pdfbox.io.IOUtils;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/*<dependency>
<groupId>org.apache.pdfbox</groupId> <artifactId>pdfbox</artifactId> <version>2.0.8</version>
</dependency>*/

public class FileOpreations {
	public InputStream getCerFileStream(boolean isClassPath, String fileName) throws FileNotFoundException {
		InputStream stream = null;
		if (isClassPath) {
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(fileName);
		} else {
			stream = new FileInputStream(fileName);
		}
		return stream;
	}
	public String getDiskFileStream_Lines( InputStream fileStream ) throws IOException {
	    StringBuffer text = new StringBuffer();
	    //FileInputStream fileStream = new FileInputStream( file );
	    BufferedReader br = new BufferedReader( new java.io.InputStreamReader( fileStream ) );
	    for ( String line; (line = br.readLine()) != null; )
	        text.append( line + System.lineSeparator() );
	    return text.toString();
	}
	public String getDiskFile_Lines( File file ) throws IOException {
	    StringBuffer text = new StringBuffer();
	    FileInputStream fileStream = new FileInputStream( file );
	    BufferedReader br = new BufferedReader( new java.io.InputStreamReader( fileStream ) );
	    for ( String line; (line = br.readLine()) != null; )
	        text.append( line + System.lineSeparator() );
	    return text.toString();
	}
	public File getFileFromStream(InputStream in) throws IOException {
		File tempFile = File.createTempFile("MyServer", ".jks");
		tempFile.deleteOnExit();
		FileOutputStream out = new FileOutputStream(tempFile);
		IOUtils.copy(in, out); // org.apache.pdfbox.io.IOUtils
		return tempFile;
	}
	
	public File getFileFromStream(InputStream in, File tempFile) throws IOException {
		FileOutputStream out = new FileOutputStream(tempFile);
		IOUtils.copy(in, out); // org.apache.pdfbox.io.IOUtils
		return tempFile;
	}
	
	// XML
	public Document getDocument(String xmlData) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		//dbf.setValidating(false);
		//dbf.setIgnoringComments(false);
		//dbf.setIgnoringElementContentWhitespace(true);
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();

		/*db.setEntityResolver(new EntityResolver() {
			@Override
			public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException
			{
				return new InputSource(new StringReader(""));
			}
		});*/
		// https://stackoverflow.com/questions/1706493/java-net-malformedurlexception-no-protocol
		// InputSource ips = new org.xml.sax.InputSource(xmlData);
		InputSource ips = new org.xml.sax.InputSource(new StringReader(xmlData));
		Document doc = db.parse(ips);
		
		return doc;
	}
	
	public String getXMLAsString(Document doc) throws TransformerException {
		DOMSource domSource = new DOMSource(doc);
		StringWriter writer = new StringWriter();
		StreamResult result = new StreamResult(writer);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trf = tf.newTransformer();
		trf.transform(domSource, result);
		String xmlStr = writer.toString();
		System.out.println("XML IN String format is:"+xmlStr);
		return xmlStr;
	}
}
