package com.github.yash777.mail;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
	static class RegexUtils {
	    static String escapeChars = "\\.?![]{}()<>*+-=^$|";
	    public static String escapeQuotes(String str) {
	        if(str != null && str.length() > 0) {
	            return str.replaceAll("[\\W]", "\\\\$0"); // \W designates non-word characters
	        }
	        return "";
	    }
	}
	public static ArrayList<String> getPrefixSufixOfFile(String fileNameIn, String regexSplit) {
		ArrayList<String> list = new ArrayList<String>();
		String prefix = "", sufix = "";
		String[] fileSplit = fileNameIn.split( RegexUtils.escapeQuotes(regexSplit) );
		for (int i = 0; i < fileSplit.length; i++) {
			
			System.out.println("Split :"+ fileSplit[i] );
			if (i+1 == fileSplit.length) {
				sufix = fileSplit[i];
			} else {
				prefix += fileSplit[i];
				if (i+2 != fileSplit.length) prefix += regexSplit;
			}
		}
		System.out.println("Prefix:"+prefix + ",  Suffix:"+sufix +", regexSplit:"+regexSplit);
		list.add(prefix);
		list.add(sufix);
		return list;
	}
	public static void main(String[] args) throws IOException {
		String fileDirecory = "C:/Yash/GZIP/IMAP2";
		String fileNameIn= "PayLoad.xml.gz", regexSplit = ".";
		
		ArrayList<String> list = getPrefixSufixOfFile(fileNameIn, regexSplit);
		String prefix = list.get(0), sufix = list.get(1);
		System.out.println("List - Prefix:"+prefix + ",  Suffix:"+sufix);
		
		//String fileNameCompressed = getFileNameWithOutExtension(fileNameIn);
		//String fileName = getFileNameWithOutExtension(fileNameCompressed);
		
		File direcoryPath = new File( fileDirecory );
		direcoryPath.mkdir();
		File tempFile = File.createTempFile(prefix, regexSplit+sufix, direcoryPath );
		
		//FileOutputStream out = new FileOutputStream(tempFile);
		//IOUtils.copy(in, out);	// org.apache.pdfbox.io.IOUtils
	}
	public static InputStream getByteOutStreamAsInputStream(ByteArrayOutputStream buffer) { // https://stackoverflow.com/a/41888647/5081877
		byte[] bytes = buffer.toByteArray();
		System.out.println("Stram Bytes:"+ new String(bytes) );
		InputStream inputStream = new ByteArrayInputStream(bytes);
		return inputStream;
	}
	public static String getFileNameWithOutExtension(String FileName) {
		// https://stackoverflow.com/a/624876/5081877
		Pattern rexExp = Pattern.compile("(.+?)(?:\\.[^\\.]*$|$)");
		Matcher matcher = rexExp.matcher(FileName);
		if (matcher.find()) {
			String file = matcher.group(1);
			System.out.println("File Name:"+ file);
			return file;
		}
		return "";
	}
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

	public String getDiskFileStream_Lines(InputStream fileStream) throws IOException {
		StringBuffer text = new StringBuffer();
		// FileInputStream fileStream = new FileInputStream( file );
		BufferedReader br = new BufferedReader(new java.io.InputStreamReader(fileStream));
		for (String line; (line = br.readLine()) != null;)
			text.append(line + System.lineSeparator());
		return text.toString();
	}

	public String getDiskFile_Lines(File file) throws IOException {
		StringBuffer text = new StringBuffer();
		FileInputStream fileStream = new FileInputStream(file);
		BufferedReader br = new BufferedReader(new java.io.InputStreamReader(fileStream));
		for (String line; (line = br.readLine()) != null;)
			text.append(line + System.lineSeparator());
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

		// dbf.setValidating(false);
		// dbf.setIgnoringComments(false);
		// dbf.setIgnoringElementContentWhitespace(true);
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
		System.out.println("XML IN String format is:" + xmlStr);
		return xmlStr;
	}
}
