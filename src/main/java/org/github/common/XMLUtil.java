package org.github.common;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/*
 * https://stackoverflow.com/questions/4076910/how-to-retrieve-element-value-of-xml-using-java
If the XML is well formed then you can convert it to Document. By using the XPath you can get the XML Elements.
 */
public class XMLUtil {
	public static void main(String[] args) throws Exception {
		String xml = "<stackusers><name>Yash</name><age>30</age></stackusers>";
		
		Document doc = getDocument(xml, true);
		//String docStr = toStringDocument(doc);
		
		String nodeVlaue = org.apache.commons.lang.StringUtils.substringBetween(xml, "<age>", "</age>");
		System.out.println("StringUtils.substringBetween():"+nodeVlaue);
		
		System.out.println("DocumentElementText:"+getDocumentElementText(doc, "age"));
		System.out.println("javax.xml.xpath.XPathFactory:"+getXPathFactoryValue(doc, "/stackusers/age"));
		
		
		//System.out.println("customer:"+getXPathFactoryValue(doc, "/customer"));
		
		System.out.println("XPathAPI:"+getNodeValue(doc, "/stackusers/age/text()"));
		NodeList nodeList = getNodeList(doc, "/stackusers");
		System.out.println("XPathAPI NodeList:"+ getXmlContentAsString(nodeList));
		System.out.println("XPathAPI NodeList:"+ getXmlContentAsString(nodeList.item(0)));
	}
	public static String getXmlContentAsString(Node node) throws TransformerException, IOException {
		StringBuilder stringBuilder = new StringBuilder();
		NodeList childNodes = node.getChildNodes();
		int length = childNodes.getLength();
		for (int i = 0; i < length; i++) {
			stringBuilder.append( toString(childNodes.item(i), true) );
		}
		return stringBuilder.toString();
	}
	
	public static String toStringDocument(Document doc) throws TransformerException {
		StringWriter sw = new StringWriter();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

		transformer.transform(new DOMSource(doc), new StreamResult(sw));
		return sw.toString();
	}
	
	public static String toString(Node document, boolean omitXmlDeclaration) throws TransformerException, IOException {
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
		stringWriter.close();
		return outputStr;
	}
	
	static XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
	public static String getXPathFactoryValue(Document doc, String xpathExpression) throws XPathExpressionException, TransformerException, IOException {
		Node node = (Node) xpath.evaluate(xpathExpression, doc, XPathConstants.NODE);
		String nodeStr = getXmlContentAsString(node);
		return nodeStr;
	}
	public static String getDocumentElementText(Document doc, String elementName) {
		return doc.getElementsByTagName(elementName).item(0).getTextContent();
	}
	
	public static String getNodeValue(Document doc, String xpathExpression) throws Exception {
		Node node = org.apache.xpath.XPathAPI.selectSingleNode(doc, xpathExpression);
		String nodeValue = node.getNodeValue();
		return nodeValue;
	}
	public static NodeList getNodeList(Document doc, String xpathExpression) throws Exception {
		NodeList result = org.apache.xpath.XPathAPI.selectNodeList(doc, xpathExpression);
		return result;
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
	
	public static String getXmlContentAsString(NodeList nodes) throws TransformerException, IOException {
		StringBuilder stringBuilder = new StringBuilder();
		int length = nodes.getLength();
		for (int i = 0; i < length; i++) {
			stringBuilder.append( toString(nodes.item(i), true) );
		}
		return stringBuilder.toString();
	}
	
	public static String toStringNode(Node node) throws TransformerException {
		StringWriter sw = new StringWriter();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

		transformer.transform(new DOMSource(node), new StreamResult(sw));
		return sw.toString();
	}
}