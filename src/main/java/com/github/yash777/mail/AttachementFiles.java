package com.github.yash777.mail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class AttachementFiles {
	private String name = "";
	private String contentType = "";
	private InputStream fileStream;
	/*public InputStream getFileStream() {
		return fileStream;
	}
	public void setFileStream(InputStream fileStream) {
		this.fileStream = fileStream;
	}*/
	private ByteArrayOutputStream outStream = new ByteArrayOutputStream();

	public byte[] getByteArray() {
		return outStream.toByteArray();
	}
	public InputStream getContent() throws Exception {
		return new ByteArrayInputStream(getByteArray());
	}
	public ByteArrayOutputStream getOutStream() {
		return outStream;
	}
	public void setOutStream(ByteArrayOutputStream outStream) {
		this.outStream = outStream;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getContentType() {
		return contentType;
	}
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}
}
