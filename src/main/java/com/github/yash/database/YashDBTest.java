package com.github.yash.database;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;

public class YashDBTest {
	
	static String ContentType = "CONTENTTYPE"; // MIMETYPE
	static String CLOB_Column = "TEXTFILE"; // TEXTCONTENT
	static String BLOB_Column = "BLOBFILE"; // BINCONTENT
	static boolean clobFile = false, blobFile = false;
	
	
	public static void main(String[] args) throws SQLException, ParseException {
		Connection conn = DBConnection.getConnection("CLOUD_DEV");
		System.out.println("DB Connection: "+ conn);
		
		try {
			String sql = "select * from YASH_INFO WHERE ID = 1";
			Map<String, Object> row = getRow(sql, conn);
			
			if (row != null) {
				String contentType = (String) row.get(ContentType);
				System.out.println("Content Type:"+contentType+"| Name:"+(String) row.get("NAME"));
				
				String str = new StringBuffer(contentType).toString();
				
				InputStream binaryStream = getReaderStram(str, row);
				Writer textWriter = getStreamWriter(binaryStream);
				System.out.println("CLOB TEXT: "+ textWriter.toString());
				if (binaryStream != null && clobFile ) {
				} else if (binaryStream != null && blobFile ) {
					
				}
				
				System.out.println("ID: "+ row.get("ID"));
				System.out.println("NAME: "+ row.get("NAME"));
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			System.out.println("Finally Closing connection...");
			conn.close();
		}
	}
	
	
	// Common Table with Column names TEXTCONTENT(CLOB), BINCONTENT(BLOB)
	public static InputStream getReaderStram(String contentType, Map<String, Object> row) throws Exception {
		InputStream binaryStream = null;
		if (contentType == "text/xml" || contentType == "text/plain" || contentType == "application/edifact") {
			// Reader initialReader = new StringReader("Some text - Commons IO");
			Reader characterStream = ((Clob) row.get( CLOB_Column )).getCharacterStream();
			// com.google.common.io.CharStreams
			binaryStream = new java.io.ByteArrayInputStream(CharStreams.toString(characterStream).getBytes(Charsets.UTF_8));
			clobFile = true;
		} else if (contentType == "application/octet-stream" || contentType == "application/vnd.ms-excel" || contentType == "application/pdf" || contentType == "application/zip") {
			binaryStream = ((Blob) row.get( BLOB_Column )).getBinaryStream();
			blobFile = true;
		} else {
			System.out.println("Unknown DataMode");
		}
		return binaryStream;
	}
	public static Map<String, Object> getRow(String sql, Connection con) {
		try {
			Map<String, Object> currentRow = null;
			PreparedStatement pst = con.prepareStatement(sql);
			try {
				ResultSet rs = pst.executeQuery();
				try {
					int colCount = pst.getMetaData().getColumnCount();
					if (rs.next()) {
						currentRow = new TreeMap<String, Object>();
						for (int col = 0; col < colCount; col++) {
							String colName = rs.getMetaData().getColumnName(col + 1);
							currentRow.put(colName, rs.getObject(col + 1));
						}
					}
				} finally {
					rs.close();
				}
			} finally {
				pst.close();
			}
			return currentRow;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// CLOB FILE
	public static String getReaderTextChar(Reader messageData) throws IOException {
		int intValueOfChar;
		StringBuilder html = new StringBuilder("");
		while ((intValueOfChar = messageData.read()) != -1) {
			html.append((char) intValueOfChar);
		}
		messageData.close();
		
		return html.toString();
	}
	public static String getReaderTextChars(Reader clobReader) throws IOException {
		char[] arr = new char[8 * 1024];
		StringBuilder buffer = new StringBuilder();
		int numCharsRead;
		while ((numCharsRead = clobReader.read(arr, 0, arr.length)) != -1) {
			buffer.append(arr, 0, numCharsRead);
		}
		clobReader.close();
		String targetString = buffer.toString();
		return targetString;
	}
	public static Writer getStreamWriter(InputStream is) throws IOException {
		// Reading from input stream and converting as string
		Writer writer = new StringWriter(); // StringBuilderWriter();
		if (is != null) {
			
			char[] buffer = new char[1024];
			InputStreamReader streamReader = new InputStreamReader(is, "UTF-8");
			Reader reader = new BufferedReader(streamReader);
			int n;
			while ((n = reader.read(buffer)) != -1) {
				writer.write(buffer, 0, n);
			}
			// Closing IO Objects
			reader.close();
			streamReader.close();
			writer.close();
		}
		return writer;
	}
}