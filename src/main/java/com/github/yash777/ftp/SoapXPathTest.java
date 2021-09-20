package com.github.yash777.ftp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class SoapXPathTest {
	public static void main(String[] args) throws Exception {
		/*
		 * String xml =
		 * "<soapenv:Body xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>" +
		 * "<Yash:Data xmlns:Yash='http://Yash.stackoverflow.com/Services/Yash'>" +
		 * "<Yash:Tags>Java</Yash:Tags><Yash:Tags>Javascript</Yash:Tags><Yash:Tags>Selenium</Yash:Tags>"
		 * + "<Yash:Top>javascript</Yash:Top><Yash:User>Yash-777</Yash:User>" +
		 * "</Yash:Data></soapenv:Body>"; String jsonNameSpaces =
		 * "{'soapenv':'http://schemas.xmlsoap.org/soap/envelope/'," +
		 * "'Yash':'http://Yash.stackoverflow.com/Services/Yash'}"; String
		 * xpathExpression = "//Yash:Data/Yash:Tags";
		 */
		
		String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
				+ "<e:Envelope xmlns:e=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:wn0=\"http://systinet.com/xsd/SchemaTypes/\">\r\n"
				+ "  <e:Header>\r\n"
				+ "    <Friends>\r\n"
				+ "      <friend>\r\n"
				+ "        <Name>Testabc</Name>\r\n"
				+ "        <Age>12121</Age>\r\n"
				+ "        <Phone>Testpqr</Phone>\r\n"
				+ "      </friend>\r\n"
				+ "    </Friends>\r\n"
				+ "  </e:Header>\r\n"
				+ "  <e:Body>\r\n"
				+ "    <n0:ForAnsiHeaderOperResponse xmlns:n0=\"http://systinet.com/wsdl/com/magicsoftware/ibolt/localhost/ForAnsiHeader/ForAnsiHeaderImpl#ForAnsiHeaderOper?KExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzs=\">\r\n"
				+ "      <response i:type=\"d:string\">12--abc--pqr</response>\r\n"
				+ "    </n0:ForAnsiHeaderOperResponse>\r\n"
				+ "  </e:Body>\r\n"
				+ "</e:Envelope>";

		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(xml.getBytes());
		MimeHeaders mimeHeaders = new MimeHeaders();
		SOAPMessage soapMsg = MessageFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL).createMessage(mimeHeaders,
				byteArrayInputStream);
		//Document docBody = soapMsg.getSOAPBody().extractContentAsDocument();
		
		String jsonNameSpaces = "{'soapenv':'http://schemas.xmlsoap.org/soap/envelope/', 'e':'http://schemas.xmlsoap.org/soap/envelope/'}"; // "//e:Header"
		String xpathExpression = "//e:Envelope/e:Header/Friends";
		
		Document doc1 = getDocument(false, "fileName", xml);
		NodeList nodeList = getNodesFromXpath(doc1, xpathExpression, jsonNameSpaces);
		
		// displayNodeList(nodeList);
		
		ArrayList<HashMap> list = new ArrayList<HashMap>();
		for (int i = 0; i < nodeList.getLength(); i++) {
			HashMap<String, String> map = new HashMap<String, String>();
			
			Node node = nodeList.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				String NodeName = node.getNodeName();
				System.out.println("NodeName:" + NodeName);
				System.out.println("Node:" + nodeToString(node));
				NodeList childNodes = node.getChildNodes();
				
				if (childNodes.getLength() > 1) {
					System.out.println("childNodes.getLength() :" + childNodes.getLength());
					for (int j = 0; j < childNodes.getLength(); j++) {
						Node child = childNodes.item(j);
						// System.out.println("NodeName:"+child.getNodeName()+",
						// Child:"+child.getChildNodes().getLength());
						if (child.getNodeType() == Node.ELEMENT_NODE) {
							String nodeValue = child.getFirstChild().getNodeValue();
							System.out.format("\n\t Node Name:[%s], Text-[%s] \n", child.getNodeName(), nodeValue);
							
							map.put(child.getNodeName(), nodeValue);
						}
					}
				}
			}
			list.add(i, map);
		}
		System.out.println("List:" + list);
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
			doc = dBuilder.parse(new File(xmlData));
		}
		return doc;
	}

	public static Document getSOAPData(javax.xml.soap.SOAPMessage soapMessage) throws SOAPException {
		return soapMessage.getSOAPBody().extractContentAsDocument();
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
				doc = builder.parse(string2Source(xml));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return doc;
	}

	/**
	 * ELEMENT_NODE[1],ATTRIBUTE_NODE[2],TEXT_NODE[3],CDATA_SECTION_NODE[4],
	 * ENTITY_REFERENCE_NODE[5],ENTITY_NODE[6],PROCESSING_INSTRUCTION_NODE[7],
	 * COMMENT_NODE[8],DOCUMENT_NODE[9],DOCUMENT_TYPE_NODE[10],DOCUMENT_FRAGMENT_NODE[11],NOTATION_NODE[12]
	 */
	public static NodeList getNodesFromXpath(Document doc, String xpathExpression, String jsonNameSpaces) {
		try {
			XPathFactory xpf = XPathFactory.newInstance();
			XPath xpath = xpf.newXPath();
			
			JSONObject namespaces = getJSONObjectNameSpaces(jsonNameSpaces);
			if (namespaces.size() > 0) {
				// 1.0.2 :
				// https://mvnrepository.com/artifact/org.apache.ws.commons.util/ws-commons-util
				org.apache.ws.commons.util.NamespaceContextImpl nsContext = new org.apache.ws.commons.util.NamespaceContextImpl();
				
				Iterator<?> key = namespaces.keySet().iterator();
				while (key.hasNext()) { // Apache WebServices Common Utilities
					String pPrefix = key.next().toString();
					String pURI = namespaces.get(pPrefix).toString();
					nsContext.startPrefixMapping(pPrefix, pURI);
				}
				xpath.setNamespaceContext(nsContext);
			}
			
			XPathExpression compile = xpath.compile(xpathExpression);
			NodeList nodeList = (NodeList) compile.evaluate(doc, XPathConstants.NODESET);
			return nodeList;

		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String nodeToString(Node node) throws TransformerException {
		StringWriter buf = new StringWriter();
		Transformer xform = TransformerFactory.newInstance().newTransformer();
		xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xform.transform(new DOMSource(node), new StreamResult(buf));
		return (buf.toString());
	}

	static void displayNodeList(NodeList nodeList) throws TransformerException {
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			String NodeName = node.getNodeName();
			System.out.println("NodeName:" + NodeName);
			System.out.println("Node:" + nodeToString(node));
			NodeList childNodes = node.getChildNodes();
			if (childNodes.getLength() > 1) {
				System.out.println("childNodes.getLength() :" + childNodes.getLength());
				for (int j = 0; j < childNodes.getLength(); j++) {
					Node child = childNodes.item(j);
					System.out.println(
							"NodeName:" + child.getNodeName() + ", Child:" + child.getChildNodes().getLength());
					short nodeType = child.getNodeType();
					if (nodeType == 1) {
						System.out.format("\n\t Node Name:[%s], Text-[%s] \n", child.getNodeName(),
								child.getNodeValue());
					}
				}
			} else {
				System.out.format("\n Node Name:[%s], Text[%s] \n", NodeName, node.getNodeValue());
			}
		}
	}

	static InputSource string2Source(String str) {
		InputSource inputSource = new InputSource(new StringReader(str));
		return inputSource;
	}

	static JSONObject getJSONObjectNameSpaces(String jsonNameSpaces) {
		if (jsonNameSpaces.indexOf("'") > -1)
			jsonNameSpaces = jsonNameSpaces.replace("'", "\"");
		JSONParser parser = new JSONParser();
		JSONObject namespaces = null;
		try {
			namespaces = (JSONObject) parser.parse(jsonNameSpaces);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return namespaces;
	}
}
/*
<!-- SOAP -->
<dependencies>
  <dependency>
    <groupId>javax.xml.soap</groupId>
    <artifactId>saaj-api</artifactId>
    <version>1.3.4</version>
    <exclusions>
      <exclusion>
        <groupId>javax.activation</groupId>
        <artifactId>activation</artifactId>
        <!-- <version>1.1.1</version> -->
      </exclusion>
    </exclusions>
  </dependency>
  <dependency>
    <groupId>javax.xml</groupId>
    <artifactId>jaxrpc-api</artifactId>
    <version>1.1</version>
  </dependency>
  <dependency>
    <groupId>org.apache.axis</groupId>
    <artifactId>axis</artifactId>
    <version>1.4</version>
  </dependency>
  <dependency>
    <groupId>wsdl4j</groupId>
    <artifactId>wsdl4j</artifactId>
    <version>1.6.2</version>
  </dependency>
  <dependency>
    <groupId>xalan</groupId>
    <artifactId>xalan</artifactId>
    <version>2.7.1</version>
  </dependency>
  <dependency>
    <groupId>xerces</groupId>
    <artifactId>xercesImpl</artifactId>
    <version>2.11.0</version>
  </dependency>
  <dependency>
    <groupId>net.sf.saxon</groupId>
    <artifactId>Saxon-HE</artifactId>
    <version>9.7.0-15</version>
  </dependency>
  <dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.5</version>
  </dependency>
  <dependency>
    <groupId>org.apache.ws.security</groupId>
    <artifactId>wss4j</artifactId>
    <version>1.6.4</version>
  </dependency>
  <dependency>
    <groupId>org.apache.cxf</groupId>
    <artifactId>cxf-rt-frontend-jaxws</artifactId>
    <version>2.2.3</version>
  </dependency>
  <dependency>
    <groupId>org.apache.cxf</groupId>
    <artifactId>cxf-rt-transports-http</artifactId>
    <version>2.2.3</version>
  </dependency>
</dependencies>
*/