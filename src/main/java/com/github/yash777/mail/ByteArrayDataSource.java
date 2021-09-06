package com.github.yash777.mail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;

public class ByteArrayDataSource implements DataSource {
	/**
	 * internal representation of data managed by this DataSouce.
	 * 
	 * @uml.property name="data" multiplicity="(0 -1)" dimension="1"
	 */
	private byte[] data; // data

	/**
	 * MIME content-type of data.
	 * 
	 * @uml.property name="contentType"
	 */
	private String contentType; // content-type

	/**
	 * Name of Data, e.g. file name of ÜNB-File.
	 * 
	 * @uml.property name="name"
	 */
	private String name; // name

	/**
	 * Creates a new ByteArrayDataSource by reading data for internal storage
	 * from inputdata.
	 * 
	 * @param inputdata
	 *            this is where our data comes from
	 * @param contentType
	 *            MIME content-type of data
	 * @param name
	 *            Name of data (ÜNB Filename for example)
	 * @throws IOException
	 *             will be thrown when reading from the InputStream fails
	 */
	public ByteArrayDataSource(InputStream inputdata, String contentType, String name)
			throws IOException {
		this.contentType = contentType;
		this.name = name;
		// CAST - Close outermost stream
		ByteArrayOutputStream internaldata =null;
		try{			
			internaldata = new ByteArrayOutputStream();
			StreamHelper.copy(inputdata, internaldata);
			data = internaldata.toByteArray();
		}finally{
			ResourceUtil.close(internaldata);
		}
	}

	/**
	 * Creates a new ByteArrayDataSource by using an array of bytes as source
	 * for internal storage.
	 * 
	 * @param inputdata
	 *            this is where our data comes from
	 * @param contentType
	 *            MIME content-type of data
	 * @param name
	 *            Name of data (ÜNB filename for example)
	 */
	ByteArrayDataSource(byte[] inputdata, String contentType, String name) {
		this.data = inputdata;
		this.contentType = contentType;
		this.name = name;
	}

	/**
	 * Return an InputStream for the data. Note - a new stream must be returned
	 * each time.
	 * 
	 * @return an InputStream newly generated, with internal data as Source.
	 * @throws IOException
	 *             if internal data is empty
	 * @see javax.activation.DataSource#getInputStream()
	 */
	public InputStream getInputStream() throws IOException {
		if (data == null) {
			throw new IOException("no data");
		}
		return new ByteArrayInputStream(data);
	}

	/**
	 * Return an OutputStream to the data. Specified by DataSource, but not
	 * implemented here. Always throws an IOException.
	 * 
	 * @return nothing. never. in no time.
	 * @throws IOException
	 *             when called (e.g. always)
	 * @see javax.activation.DataSource#getOutputStream()
	 */
	public OutputStream getOutputStream() throws IOException {
		throw new IOException("cannot do this");
	}

	/**
	 * get the MIME content-type of this instance.
	 * 
	 * @return a String containing the content type of data stored within this
	 *         instance.
	 * @see javax.activation.DataSource#getContentType()
	 * @uml.property name="contentType"
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * get the name of the data stored within this instance.
	 * 
	 * @return the name of our data
	 * @see javax.activation.DataSource#getName()
	 * @uml.property name="name"
	 */
	public String getName() {
		return name;
	}

}
