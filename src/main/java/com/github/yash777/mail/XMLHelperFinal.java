package com.github.yash777.mail;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xpath.XPathAPI;
import org.json.simple.parser.JSONParser;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * This class collects common used XML functionality. It provides no instance of
 * itself, because all work is done using static methods.
 * 
 */
public final class XMLHelperFinal {
	private final static Log log = LogFactory.getLog(XMLHelperFinal.class);

	public static void main(String[] args) throws XPathExpressionException, TransformerException {
		String xml = "<e:Envelope\r\n" + "    xmlns:d = \"http://www.w3.org/2001/XMLSchema\"\r\n"
				+ "    xmlns:e = \"http://schemas.xmlsoap.org/soap/envelope/\"\r\n"
				+ "    xmlns:wn0 = \"http://systinet.com/xsd/SchemaTypes/\"\r\n"
				+ "    xmlns:i = \"http://www.w3.org/2001/XMLSchema-instance\">\r\n" + "    <e:Header>\r\n"
				+ "        <Friends>\r\n" + "            <friend>\r\n" + "                <Name>Testabc</Name>\r\n"
				+ "                <Age>12121</Age>\r\n" + "                <Phone>Testpqr</Phone>\r\n"
				+ "            </friend>\r\n" + "        </Friends>\r\n" + "    </e:Header>\r\n" + "    <e:Body>\r\n"
				+ "        <n0:ForAnsiHeaderOperResponse xmlns:n0 = \"http://systinet.com/wsdl/com/magicsoftware/ibolt/localhost/ForAnsiHeader/ForAnsiHeaderImpl#ForAnsiHeaderOper?KExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzs=\">\r\n"
				+ "            <response i:type = \"d:string\">12--abc--pqr</response>\r\n"
				+ "        </n0:ForAnsiHeaderOperResponse>\r\n" + "    </e:Body>\r\n" + "</e:Envelope>";

		String jsonNameSpaces = "{'soapenv':'http://schemas.xmlsoap.org/soap/envelope/'}";
		String xpathExpression = "//Envelope//Header";

		Document doc = getDocument(false, "fileName", xml);
		System.out.println("DOC:" + doc);
		XPath xpath = XPathFactory.newInstance().newXPath();
		Node result = (Node) xpath.evaluate(xpathExpression, doc, XPathConstants.NODE);
		System.out.println(nodeToString(result));

		// <dependency> <groupId>org.apache.santuario</groupId>
		// <artifactId>xmlsec</artifactId> <version>1.4.5</version> </dependency>
		/*
		 * Node node = org.apache.xpath.XPathAPI.selectSingleNode(doc, xpathExpression);
		 * String nodeValue = node.getNodeValue();
		 * System.out.format("Node:%-40s, V:%s\n", xpath, nodeValue);
		 */

		/*
		 * XPath xpath = getNameSpaceXpath(null); XPathExpression compile =
		 * xpath.compile(xpathExpression); NodeList nodeList = (NodeList)
		 * compile.evaluate(doc, XPathConstants.NODE); displayNodeList(nodeList);
		 */

	}

	private static String nodeToString(Node node) throws TransformerException {
		StringWriter buf = new StringWriter();
		Transformer xform = TransformerFactory.newInstance().newTransformer();
		xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xform.transform(new DOMSource(node), new StreamResult(buf));
		return (buf.toString());
	}
	/* <!-- https://mvnrepository.com/artifact/org.apache.ws.commons.util/ws-commons-util -->
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
		</dependency> */
	public static javax.xml.xpath.XPath getNameSpaceXpath(String jsonNameSpaces) {
		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();

		if (jsonNameSpaces != null) {
			org.json.simple.JSONObject namespaces = getJSONObjectNameSpaces(jsonNameSpaces);
			if (namespaces.size() > 0) {
				// 1.0.2 :
				// https://mvnrepository.com/artifact/org.apache.ws.commons.util/ws-commons-util
				// org.apache.ws.commons.util.NamespaceContextImpl
				org.apache.ws.commons.util.NamespaceContextImpl nsContext = new org.apache.ws.commons.util.NamespaceContextImpl();

				Iterator<?> key = namespaces.keySet().iterator();
				while (key.hasNext()) { // Apache WebServices Common Utilities
					String pPrefix = key.next().toString();
					String pURI = namespaces.get(pPrefix).toString();
					nsContext.startPrefixMapping(pPrefix, pURI);
				}
				xpath.setNamespaceContext(nsContext);
			}
		}
		return xpath;
	}
	/* <!-- https://mvnrepository.com/artifact/com.googlecode.json-simple/json-simple -->
		<dependency>
		    <groupId>com.googlecode.json-simple</groupId>
		    <artifactId>json-simple</artifactId>
		    <version>1.1</version>
		</dependency> */
	static org.json.simple.JSONObject getJSONObjectNameSpaces(String jsonNameSpaces) {
		// 1.1 :
		// https://mvnrepository.com/artifact/com.googlecode.json-simple/json-simple
		if (jsonNameSpaces.indexOf("'") > -1)
			jsonNameSpaces = jsonNameSpaces.replace("'", "\"");
		org.json.simple.parser.JSONParser parser = new org.json.simple.parser.JSONParser();
		org.json.simple.JSONObject namespaces = null;
		try {
			namespaces = (org.json.simple.JSONObject) parser.parse(jsonNameSpaces);
		} catch (org.json.simple.parser.ParseException e) {
			e.printStackTrace();
		}
		return namespaces;
	}

	static Document getDocument(boolean isFileName, String fileName, String xml) {
		Document doc = null;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);
			factory.setIgnoringComments(true);
			factory.setIgnoringElementContentWhitespace(true);

			DocumentBuilder builder = factory.newDocumentBuilder();
			if (isFileName) {
				File file = new File(fileName);
				FileInputStream stream = new FileInputStream(file);
				doc = builder.parse(stream);
			} else {
				InputSource inputSource = new InputSource(new StringReader(xml));
				doc = builder.parse(inputSource);
			}
		} catch (SAXException | IOException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
		return doc;
	}

	static void displayNodeList(NodeList nodeList) {
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			String NodeName = node.getNodeName();

			NodeList childNodes = node.getChildNodes();
			if (childNodes.getLength() > 1) {
				for (int j = 0; j < childNodes.getLength(); j++) {

					Node child = childNodes.item(j);
					short nodeType = child.getNodeType();
					if (nodeType == 1) {
						System.out.format("\n\t Node Name:[%s], Text[%s] ", child.getNodeName(), child.getNodeValue());
					}
				}
			} else {
				System.out.format("\n Node Name:[%s], Text[%s] ", NodeName, node.getNodeValue());
			}

		}
	}

	/**
	 * Returns a DOM XML Document for a Reader. This method simply encapsulates
	 * logistic overhead for building a parser, parse data and catch exceptions.
	 * 
	 * @param xmldata - A reader containing the data.
	 * @return DOM XML Document containing the data.
	 */
	public static Document parseReader(Reader xmldata) {
		Document result = null;
		try {
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
		String outputStr = stringWriter.toString();
		ResourceUtil.close(stringWriter);
		return outputStr;
	}

	public static String getXmlContentAsString(Node node) throws TransformerException {
		StringBuilder stringBuilder = new StringBuilder();
		NodeList childNodes = node.getChildNodes();
		int length = childNodes.getLength();
		for (int i = 0; i < length; i++) {
			stringBuilder.append(toString(childNodes.item(i), true));
		}
		return stringBuilder.toString();
	}

	/**
	 * Returns a DOM XML Document for a String. This method simply encapsulates
	 * logistic overhead for building a parser, parse data and catch exceptions.
	 * 
	 * @param xml the String to parse
	 * @return an XML document as DOM tree.
	 */
	public static Document parseString(String xml) {
		Document result = null;
		StringReader stringReader = null;
		InputSource source = null;
		DocumentBuilder builder = null;

		try {
			builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			stringReader = new StringReader(xml);
			source = new InputSource(stringReader);
			result = builder.parse(source);
		} catch (ParserConfigurationException e) {
			log.error(e, e);
		} catch (IOException e) {
			log.error(e, e);
		} catch (SAXException e) {
			log.error(e, e);
		} finally {
			if (stringReader != null) {
				stringReader.close();
			}

			stringReader = null;
			source = null;
			builder = null;
		}
		return result;
	}

	/**
	 * Finds a node in a context by a given XPath expression.
	 * 
	 * @param context can be any type of Node, including whole documents
	 * @param xpath   a String defining the XPath expression.
	 * @return node or tree of nodes containing search results
	 */
	public static Node getNode(Node context, String xpath) {
		Node result = null;
		try {
			result = XPathAPI.selectSingleNode(context, xpath);
		} catch (TransformerException e) {
			throw new Error("XPath search could not be performed: " + e.getMessage(), e);
		}
		return result;
	}

	/**
	 * Finds a list of nodes in the context by a given XPath expression. Does
	 * roughly the same as getNode(). This method should be used instead of
	 * getNode() if more than one node could be returned from the XML data. If in
	 * doubt, use this method.
	 * 
	 * @param context the XML document (or part of it) in which we want to evaluate
	 *                the XPath expression (e.g. find nodes)
	 * @param xpath   a valid XPath expression describing the node(s) to be searched
	 *                for.
	 * @return a NodeList containing the search results.
	 */
	public static NodeList getNodes(Node context, String xpath) {
		NodeList result = null;
		try {
			result = XPathAPI.selectNodeList(context, xpath);
		} catch (TransformerException e) {
			throw new Error("XPath search could not be performed: " + e.getMessage(), e);
		}
		return result;
	}

	/**
	 * This method performs a search in the given context. A description of the
	 * nodes to be searched for is provided in an XPath expression. The third
	 * parameter, mandatory, describes if the search should always return something,
	 * e.g. the corresponding node is mandatory. This method is actually a call to
	 * getNode, followed by getNodeValue(). But since we need additional checking to
	 * accomplish this, it encapsulated herein.
	 * 
	 * @param context   the XML document (or part of it) in which we want to
	 *                  evaluate the XPath expression (e.g. find nodes)
	 * @param xpath     a valid XPath expression describing the node(s) to be
	 *                  searched for.
	 * @param mandatory is the node described by xpath mandatory?
	 * @return node or tree of nodes containing search results
	 * @throws MailPreparingException thrown is mandatory is true but search result
	 *                                is empty.
	 */
	public static String getNodeAsString(Node context, String xpath, boolean mandatory) throws MailPreparingException {
		Node node = getNode(context, xpath);

		String result = null;

		if (node == null) {
			if (mandatory) {
				throw new MailPreparingException("", "Pflichtfeld darf nicht leer sein: " + xpath);
			} else {
				result = null;
			}
		} else {
			result = node.getNodeValue();
		}
		return result;
	}

	/**
	 * This method performs a search in the given context. A description of the
	 * nodes to be searched for is provided in an XPath expression. The third
	 * parameter, mandatory, describes if the search should always return something,
	 * e.g. the corresponding node is mandatory. This method is actually a call to
	 * getNodes. But since we need additional checking to accomplish this, it
	 * encapsulated herein.
	 * 
	 * @param context   the XML document (or part of it) in which we want to
	 *                  evaluate the XPath expression (e.g. find nodes)
	 * @param xpath     a valid XPath expression describing the node(s) to be
	 *                  searched for.
	 * @param mandatory is the node described by xpath mandatory?
	 * @return node list of nodes containing search results
	 * @throws MailPreparingException thrown is mandatory is true but search result
	 *                                is empty.
	 */

	public static NodeList getNodeList(Node context, String xpath, boolean mandatory) throws MailPreparingException {
		NodeList result = getNodes(context, xpath);

		if (result == null) {
			if (mandatory) {
				throw new MailPreparingException("", "Pflichtfeld darf nicht leer sein: " + xpath);
			}
		}
		return result;
	}

	/**
	 * Returns the contents of a XML search as Map. useful if handling name-value
	 * pairs.
	 * 
	 * @param context   root node to search beneath.
	 * @param xpath     XPath search expression.
	 * @param mandatory should be set to true if result must not be empty.
	 * @return a Map containing "name"-"value" pairs.
	 * @throws MailPreparingException if mandatory is set to true and result would
	 *                                be empty.
	 */
	public static OrderedMap getValuesMap(Node context, String xpath, boolean mandatory, String keyTag, String valueTag)
			throws MailPreparingException {
		NodeList nl = XMLHelperFinal.getNodeList(context, xpath, mandatory);

		OrderedMap values = new HashOrderedMap();
		if (nl != null) {
			for (int i = 0; i < nl.getLength(); i++) {
				Node n = nl.item(i);

				String value = XMLHelperFinal.getNodeAsString(n, "@" + valueTag, false);
				String key = XMLHelperFinal.getNodeAsString(n, "@" + keyTag, false);

				if ((key != null) && (value != null)) {
					values.add(key, value);
				} else {
					throw new MailPreparingException("", "Name oder Value-Knoten fehlt in Eintrag!");
				}
			}
		}

		return values;

	}

	public static String extractTextFromXml(String xml) {
		String result = xml.replaceAll("<[^>]+>", "");
		return result.replaceAll("\\s+", " ").trim();
	}

	/**
	 * Private constructor, so this class cannot be instantiated.
	 */
	private XMLHelperFinal() {
	}

	public static String encodeXMLSpecialChars(String str) {
		str = str.replaceAll("&", "&amp;"); // & --> &amp;
		str = str.replaceAll("<", "&lt;"); // < --> &lt;
		str = str.replaceAll(">", "&gt;"); // > --> &gt;
		str = str.replaceAll("'", "&apos;"); // ' --> &apos;
		str = str.replaceAll("\"", "&quot;"); // " --> &quot;
		return str;
	}

	public static String decodeXMLSpecialChars(String str) {
		str = str.replaceAll("&amp;", "&");
		str = str.replaceAll("&lt;", "<");
		str = str.replaceAll("&gt;", ">");
		str = str.replaceAll("&apos;", "'");
		str = str.replaceAll("&quot;", "\"");
		return str;
	}

	public static String serializeXML(Document doc, boolean indent, boolean omitXmlDeclaration) {
		Transformer transformer;
		try {
			transformer = TransformerFactory.newInstance().newTransformer();
			if (indent)
				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			if (omitXmlDeclaration)
				transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

			// initialize StreamResult with File object to save to file
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(doc);
			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();

			return xmlString;

		} catch (TransformerConfigurationException e) {
			throw new Error("XML Library malfunction: " + e.getMessage(), e);
		} catch (TransformerFactoryConfigurationError e) {
			throw new Error("XML Library malfunction: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new Error("XML Library malfunction: " + e.getMessage(), e);
		}
	}

	public static HashMap<String, File> writeSourceToFiles(Reader inhouseContentReader, InputStream templateInputStream,
			String sessionAsString) {
		HashMap<String, File> returnMap = new HashMap<String, File>();

		try {
			BufferedReader xmlbufferedReader = new BufferedReader(inhouseContentReader);
			BufferedInputStream xslbufferedInputStream = new BufferedInputStream(templateInputStream);

			ResourceBundle loggingProps = ResourceBundle.getBundle("environment");
			String sourceDir = loggingProps.getString("xmlpathForconversion");// --
			// /webdienste/appserv-jsp/tomcat/neon.intranet.eon-energy-trading.com/current/logs

			Date dateNow = new Date();

			SimpleDateFormat dateFormat = new SimpleDateFormat("dd_MM_yy_HH_mm_ss_SS");
			String dateInStr = dateFormat.format(dateNow);
			FileOutputStream xmlfileOpStream = null;
			OutputStreamWriter xmlOutputStreamWriter = null;
			BufferedWriter xmlbufferedWriter = null;

			FileOutputStream xslfileOpStream = null;
			BufferedWriter xslbufferedWriter = null;
			OutputStreamWriter xslOutputStreamWriter = null;

			String xmlpathForconversion = sourceDir + File.separator + sessionAsString;
			File sourceFolderLocaiton = new File(xmlpathForconversion);

			if (!sourceFolderLocaiton.exists()) {
				sourceFolderLocaiton.mkdirs();
			}

			dateInStr = dateInStr + "_" + UUID.randomUUID();
			File xmlOutputFile = new File(xmlpathForconversion + File.separator + "XMLSource_" + dateInStr + ".xml");
			File xslOutputFile = new File(xmlpathForconversion + File.separator + "XSLSource_" + dateInStr + ".xsl");
			File resultOutputFile = new File(xmlpathForconversion + File.separator + "XMLResult_" + dateInStr + ".xml");

			returnMap.put("xmlOutputFile", xmlOutputFile);
			returnMap.put("xslOutputFile", xslOutputFile);
			returnMap.put("resultOutputFile", resultOutputFile);

			try {
				xmlOutputFile.createNewFile();
				xslOutputFile.createNewFile();
			} catch (IOException e) {
				log.error(e, e);
			}

			try {
				xmlfileOpStream = new FileOutputStream(xmlOutputFile, false);
				xmlOutputStreamWriter = new OutputStreamWriter(xmlfileOpStream, "UTF-8");
				xmlbufferedWriter = new BufferedWriter(xmlOutputStreamWriter);

				xslfileOpStream = new FileOutputStream(xslOutputFile, false);
				xslOutputStreamWriter = new OutputStreamWriter(xslfileOpStream, "UTF-8");

				xslbufferedWriter = new BufferedWriter(xslOutputStreamWriter);

				int eachByte = xmlbufferedReader.read();
				while (eachByte != -1) {
					xmlbufferedWriter.write(eachByte);
					eachByte = xmlbufferedReader.read();
				}

				xmlbufferedWriter.flush();

				eachByte = xslbufferedInputStream.read();

				while (eachByte != -1) {
					xslbufferedWriter.write(eachByte);
					eachByte = xslbufferedInputStream.read();
				}

				xslbufferedWriter.flush();
			} catch (IOException e) {
				log.error(e, e);
			} finally {
				if (xslbufferedWriter != null) {
					try {
						xslbufferedWriter.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xmlbufferedWriter != null) {
					try {
						xmlbufferedWriter.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xmlOutputStreamWriter != null) {
					try {
						xmlOutputStreamWriter.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xslOutputStreamWriter != null) {
					try {
						xslOutputStreamWriter.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xslfileOpStream != null) {
					try {
						xslfileOpStream.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xmlfileOpStream != null) {
					try {
						xmlfileOpStream.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xmlbufferedReader != null) {
					try {
						xmlbufferedReader.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}

				if (xslbufferedInputStream != null) {
					try {
						xslbufferedInputStream.close();
					} catch (IOException e) {
						log.error(e, e);
					}
				}
			}
		} catch (Throwable t) {
			log.error("Problem in --writeSourceToFiles--" + t.toString());
			log.error(t, t);
		}

		return returnMap;
	}

	public static void purgeTemporaryFiles(HashMap<String, File> returnMap) {
		Collection<File> files = returnMap.values();
		Iterator<File> filesIterator = files.iterator();
		File eachFile = null;

		while (filesIterator.hasNext()) {
			eachFile = filesIterator.next();
			boolean deleteOperation = eachFile.delete();

			if (!deleteOperation) {
				log.error("Unable to delete TEMP files for Convert operation" + eachFile.getAbsolutePath());
			}
		}

		if (eachFile != null && eachFile.getParentFile() != null) {
			boolean deleteOperation = eachFile.getParentFile().delete();

			if (!deleteOperation) {
				log.error(
						"Unable to delete TEMP files Session folder for Convert operation" + eachFile.getParentFile());
			}
		}

		files = null;
		filesIterator = null;
		eachFile = null;
	}
}
