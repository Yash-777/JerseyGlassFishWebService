package com.github.yash777.ftp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.SourceLocator;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.github.yash777.mail.ResourceUtil;

// https://github.com/Yash-777/XML_XSL-tester/wiki/XML-_-XSL-%5BXSLT,-XPath,-XQuery%5D
// https://www.online-toolz.com/tools/xslt-transformation.php
public class XSL_Transformer {
	static String filePath = "C:\\Yash\\XSLTTransformer\\";
	public static void main(String[] args) throws Exception {
		String xmlFile = filePath+"XML_Input.xml", xsltFile = filePath+"XSL_Input.xsl", 
				xmlTransformedFile = filePath+"XMLTransformed_Output.xml";
		
		InputStream XMLStream = new FileInputStream(xmlFile);
		InputStream	XSLTStream = new FileInputStream(xsltFile);
		OutputStream TransFormedXMLStream = new FileOutputStream(xmlTransformedFile);
		XSLT_Transformer(XMLStream, XSLTStream, TransFormedXMLStream);
	}
	
	// Takes Reader and creates no.of Copies and returns list.
	public static List<Reader> multiply(Reader reader, int noOfCopies) throws IOException {
		List<Reader> copies = new ArrayList<Reader>();
		BufferedReader bufferedInput = new BufferedReader(reader);
		StringBuffer buffer = new StringBuffer();
		String delimiter = System.getProperty("line.separator");
		String line;
		while ((line = bufferedInput.readLine()) != null) {
			if (!buffer.toString().equals(""))
				buffer.append(delimiter);
			buffer.append(line);
		}
		bufferedInput.close();
		for (int i = 0; i < noOfCopies; i++) {
			copies.add(new StringReader(buffer.toString()));
		}
		return copies;
	}

	public static String getDiskFile_Lines( File file ) throws IOException {
		StringBuffer text = new StringBuffer();
		FileInputStream fileStream = new FileInputStream( file );
		BufferedReader br = new BufferedReader( new java.io.InputStreamReader( fileStream ) );
		for ( String line; (line = br.readLine()) != null; )
			text.append( line + System.lineSeparator() );
		return text.toString();
	}
	
	public static String XSLT_Transformer(String xmlContent, String xslContent) {
		try {
			StringReader readerXML = new StringReader(xmlContent);
			StringReader readerXSL = new StringReader(xslContent);
			StringWriter writer = new StringWriter();
			
			// Create transformer factory
			TransformerFactory factory = javax.xml.transform.TransformerFactory.newInstance();
			
			// Use the factory to create a template containing the xsl file
			StreamSource streamSource = new StreamSource(readerXSL);
			Templates template = factory.newTemplates(streamSource);
			
			// Use the template to create a transformer
			Transformer xformer = template.newTransformer();
			
			// Prepare the input and output files
			Source source = new StreamSource(readerXML);
			StreamResult result = new javax.xml.transform.stream.StreamResult(writer);
			
			// Apply the xsl file to the source file and write the result to the output file
			xformer.transform(source, result);
			
			String transformedXML = writer.toString();
			return transformedXML;
		} catch (TransformerConfigurationException e) {
			// An error occurred in the XSL file
		} catch (TransformerException e) { // An error occurred while applying the XSL file
			SourceLocator locator = e.getLocator();
			System.out.println("Get location of error in input file :" +locator);
		}
		return null;
	}
	
	public static void XSLT_Transformer(InputStream XMLStream, InputStream XSLTStream, OutputStream TransFormedXMLStream) {
		try {
			// Create transformer factory
			TransformerFactory factory = javax.xml.transform.TransformerFactory.newInstance();
			
			// Use the factory to create a template containing the xsl file
			StreamSource streamSource = new StreamSource(XSLTStream);
			Templates template = factory.newTemplates(streamSource);
			
			// Use the template to create a transformer
			Transformer xformer = template.newTransformer();
			
			// Prepare the input and output files
			Source source = new StreamSource(XMLStream);
			Result result = new StreamResult(TransFormedXMLStream);
			
			// Apply the xsl file to the source file and write the result to the output file
			xformer.transform(source, result);
		} catch (TransformerConfigurationException e) {
			// An error occurred in the XSL file
		} catch (TransformerException e) { // An error occurred while applying the XSL file
			SourceLocator locator = e.getLocator();
			System.out.println("Get location of error in input file :" +locator);
		}
	}
	
	public static Node getNode(Node context, String xpath) {
		Node result = null;
		try {
			result = XPathAPI.selectSingleNode(context, xpath);
		} catch (TransformerException e) {
			throw new Error("XPath search could not be performed: " + e.getMessage(), e);
		}
		return result;
	}
	public static NodeList getNodes(Node context, String xpath) {
		NodeList result = null;
		try {
			result = XPathAPI.selectNodeList(context, xpath);
		} catch (TransformerException e) {
			throw new Error("XPath search could not be performed: " + e.getMessage(), e);
		}
		return result;
	}
	public static String toString(Node document, boolean omitXmlDeclaration) throws TransformerException {
		StringWriter stringWriter = new StringWriter();
		StreamResult streamResult = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = (SAXTransformerFactory) new net.sf.saxon.TransformerFactoryImpl();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
		transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, omitXmlDeclaration ? "yes" : "no");
		transformer.transform(new DOMSource(document), streamResult);
		// CAST - Close outermost stream
		String outputStr=stringWriter.toString();
		ResourceUtil.close(stringWriter);
		return outputStr;
	}
	public static Document parseReader(Reader xmldata) {
		Document result = null;
		try  {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			// factory.setIgnoringElementContentWhitespace(false);
			result = builder.parse(new InputSource(xmldata));
		} catch (FactoryConfigurationError e) {
			throw new Error("Error instantiating XML parser: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			// parser was unable to be configured
			throw new Error("Error instantiating XML parser: " + e.getMessage(), e);
		} catch (SAXException e) {
			throw new Error("Syntax error in the XML data: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new Error("Input / output error when parsing the XML document: " + e.getMessage(), e);
		}
		return result;
	}
}

/**
#### XML_Input.xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns:foo="http://www.foo.org/">
  <dependencies>
    <dependency>
        <groupId>javax.xml.soap</groupId>
        <artifactId>saaj-api</artifactId>
        <version>1.3.4</version>
    </dependency>
    <dependency>
        <groupId>javax.xml</groupId>
        <artifactId>jaxrpc-api</artifactId>
        <version>1.1</version>
    </dependency>
  </dependencies>
</project>


#### XSL_Input.xsl
<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
  xmlns:foo="http://www.foo.org/" exclude-result-prefixes="foo xsl">
  
  <xsl:decimal-format name="de" decimal-separator="," grouping-separator="." />
  <xsl:output method="xml" indent="yes" />
  
  <xsl:decimal-format name="de" decimal-separator="," grouping-separator="." />
    
  <xsl:template match="/"> <xsl:apply-templates /> </xsl:template>
  
  <xsl:template match="project">
    <projectSample xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:foo="http://www.foo.org/">
      <!-- their can be multiple parent tags, So use templates/for-each for parent also -->
      <xsl:apply-templates select="dependencies" />
    </projectSample>
  </xsl:template>
    
  <xsl:template match="dependencies">
    <dependencies> <xsl:apply-templates select="dependency" /> </dependencies>
  </xsl:template>
  
  <xsl:template match="dependency">
    <dependency>  
    <!-- We can also use xsl:choose > when,Otherwise -->
    <xsl:value-of select="groupId" /> : <xsl:value-of select="artifactId" /> : <xsl:value-of select="version" /> 
    </dependency>
  </xsl:template>
</xsl:stylesheet>

#### XMLTransformed_Output.xml
<?xml version="1.0" encoding="UTF-8"?><projectSample xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dependencies>
<dependency>javax.xml.soap : saaj-api : 1.3.4</dependency>
<dependency>javax.xml : jaxrpc-api : 1.1</dependency>
</dependencies>
</projectSample>

*/