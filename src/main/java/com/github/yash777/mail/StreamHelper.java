package com.github.yash777.mail;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class StreamHelper {

	/**
	 * Copies the input stream into the output stream.
	 * 
	 * @param in the InputStream
	 * @param out the OutputStream
	 * @throws IOException
	 *    if reading the InputStream or writing into the OutputStream goes wrong.
	 */
	public static void copy(InputStream in, OutputStream out)
			throws IOException {
		try {
			byte[] buffer = new byte[1024];
			int nrOfBytes = -1;
			while ((nrOfBytes = in.read(buffer)) != -1) {
				out.write(buffer, 0, nrOfBytes);
			}
			out.flush();
		} finally {
			try {
				in.close();
			} finally {
				out.close();
			}
		}
	}

	/**
	 * Copies the Reader contents into the Writer.
	 * 
	 * @param in the Reader
	 * @param out the Writer
	 * @throws IOException
	 *      if reading the Reader or Writing into the Writer goes wrong.
	 */
	public static void copy(Reader in, Writer out) throws IOException {
		try {
			char[] buffer = new char[1024];
			int nrOfBytes = -1;
			while ((nrOfBytes = in.read(buffer)) != -1) {
				out.write(buffer, 0, nrOfBytes);
			}
			out.flush();
		} finally {
			try {
				in.close();
			} finally {
				out.close();
			}
		}
	}

	/**
	 * Creates a ZIP stream from the given OutputStream and writes the
	 * NamedContent elements into the ZIP archive.
	 * 
	 * @param contents > the list of NamedContent elements
	 * @param outstream > the destination stream
	 */
	public static void zip(List contents, OutputStream outstream) throws Exception {
		Map usedFilenames = new HashMap(); // store filename to assure unique
		// filenames (required by ZIP)

		ByteArrayOutputStream zippedBuffer = new ByteArrayOutputStream();
		// CAST - Close outermost stream
		ByteArrayInputStream byteStream = null;
		try {
			ZipOutputStream out = new ZipOutputStream(zippedBuffer);
			try {
				// Create a buffer for reading the files
				byte[] buf = new byte[1024];

				// Compress the files
				for (Iterator it = contents.iterator(); it.hasNext();) {
					AttachementFiles content = (AttachementFiles) (it.next());
					InputStream in;
					in = content.getContent();
					try {

						// Acquire unique filename
						String filename = content.getName();
						Integer count = (Integer) usedFilenames.get(filename);
						if (count == null)
							count = new Integer(0);

						count = new Integer(count.intValue() + 1);
						usedFilenames.put(filename, count);

						if (count.intValue() > 1)
							filename = count.toString() + "_" + filename;

						// Add ZIP entry to output stream.
						out.putNextEntry(new ZipEntry(filename));
						try {

							// Transfer bytes from the file to the ZIP file
							int len;
							while ((len = in.read(buf)) > 0) {
								out.write(buf, 0, len);
							}

						} finally {
							// Complete the entry
							out.closeEntry();
						}
					} finally {
						in.close();
					}
				}

				// Complete the ZIP file
				out.flush();
			} finally {
				out.close();
			}

			// copy zipped contents to outputstream
			byteStream = new ByteArrayInputStream(zippedBuffer.toByteArray());
			StreamHelper.copy(byteStream,outstream);

		} catch (IOException e) {
			throw new Exception("Fehler beim Komprimieren der Daten", e);
		}// CAST - Close outermost stream
		finally{			
			ResourceUtil.close(byteStream);
		}
	}

	/**
	 * Takes the reader, multiplies it <code>amount</code> times and returns the
	 * created Readers as a List.
	 * 
	 * @param reader > the data source for the clone warriors.
	 * @param amount > how many Readers to create.
	 * @return a List of Readers, all containing the same data as the Reader
	 *         given as an argument.
	 */
	public static List<Reader> multiply(Reader reader, int amount)
			throws IOException {
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
		ResourceUtil.close(bufferedInput);
		for (int i = 0; i < amount; i++) {
			copies.add(new StringReader(buffer.toString()));
		}
		return copies;

	}

	/**
	 * Prints the contents of the reader to System.out.
	 * 
	 * @param reader > data source for output.
	 * @throws IOException > if processing the reader fails.
	 */
	public static void printReader(Reader reader) throws IOException {
		BufferedReader br = new BufferedReader(reader);
		String s;
		while ((s = br.readLine()) != null) {
			System.out.println(s);
		}
	}

	/**
	 * Prints the contents of the InputStream to System.out.
	 * 
	 * @param inputStream > data source for output.
	 * @throws IOException > if processing the Stream fails.
	 */
	public static void printInputStream(InputStream inputStream)
			throws IOException {
		printReader(new InputStreamReader(inputStream));
	}

	/**
	 * empty private constructor, so this class is static only.
	 */
	private StreamHelper() {
	}
	
	public static String getCLOBText(Reader clobReader) throws IOException {
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
}
