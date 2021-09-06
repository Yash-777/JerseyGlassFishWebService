package org.github.glassfish.jersey.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;

public class GZIP_Util {
	static String tempFilePath = "C:/Yash/GZIP/"; // application/x-gzip
	
	// HTTP - InputStream to String [To decode bytes from an InputStream]
	public String getHTTPStreamContent(InputStream input, String encoding) throws IOException {
		byte[] httpResponse;
		String httpResponseString;
		httpResponse = org.apache.commons.io.IOUtils.toByteArray(input);
		System.out.println("Byte Array:"+httpResponse.toString());
		if (encoding == null) {
			httpResponseString = new String(httpResponse);
		} else if ( encoding.equalsIgnoreCase("GZIP") ) { // https://stackoverflow.com/a/3627442/5081877
			httpResponseString = getDeCompressedString(httpResponse);
		} else { // "ISO-8859-1", ";TF-8"
			httpResponseString = new String(httpResponse, encoding);
		}
		System.out.println("getHTTPStreamContent: Resposne - "+httpResponseString);
		return httpResponseString;
	}
	public String getDeCompressedString(byte[] zipBytes) {
		try {
			ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(zipBytes);
			GZIPInputStream gzipInput = new GZIPInputStream( byteArrayInputStream );
			return org.apache.commons.io.IOUtils.toString(gzipInput);
		} catch (IOException e) {
			throw new java.io.UncheckedIOException("Error while decompression!", e);
		}
	}
	
	// SMTP - Attachment file compression to *.xml.gz and uncompressed to *.xml
	// https://www.javatips.net/api/org.apache.commons.compress.compressors.gzip.gzipcompressoroutputstream
	public static void compressCommons(InputStream streamSrc, String fileName, OutputStream gipStream) throws IOException {
		GzipParameters parameters = new GzipParameters();
		parameters.setCompressionLevel(Deflater.BEST_SPEED);
		parameters.setFilename( fileName );
		parameters.setModificationTime( (new java.util.Date()).getTime() );
		
		GzipCompressorOutputStream out = new GzipCompressorOutputStream(gipStream, parameters); // zipFile
		
		byte[] buf = new byte[10240];
		while (true) {
			int len = streamSrc.read(buf);
			if (len <= 0) {
				break;
			}
			out.write(buf, 0, len);
		}
		out.flush();
		out.close();
		streamSrc.close();
	}
	public static HashMap<String, ByteArrayOutputStream> unCompressCommons(InputStream gzipStream) throws IOException {
		HashMap<String, ByteArrayOutputStream> gzipContent = new HashMap<String, ByteArrayOutputStream>();
		
		//FileInputStream fin = new FileInputStream(compressInputFile);
		//BufferedInputStream bIn = new BufferedInputStream(fin);
		GzipCompressorInputStream gcis = new GzipCompressorInputStream( gzipStream );
		String filename = gcis.getMetaData().getFilename();
		System.out.println("GZIP File name :"+filename);
		
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int len;
		while ((len = gcis.read(buffer)) != -1) {
			outStream.write(buffer, 0, len);
		}
		if (filename == null) {
			gzipContent.put("RawBytes", outStream);
			
			byte[] byteArray = outStream.toByteArray();
			System.out.println("Raw Bytes : "+ new String(byteArray, "UTF-8") );
		} else {
			gzipContent.put(filename, outStream);
			
			byte[] byteArray = outStream.toByteArray();
			System.out.println(filename+" : "+ new String(byteArray, "UTF-8") );
			
			org.apache.commons.io.FileUtils.writeByteArrayToFile(new File(tempFilePath+"commons/"+filename), byteArray);
		}
		return gzipContent;
	}
	
	public static void main(String[] args) throws Exception {
		String attachementFile = tempFilePath +
				//"archive.gz";
				//"PayLoad.xml.gz";
				"MailSampleAttachement_20210614_132242.xml.gz";
		File zipFile_SMTP = new File(attachementFile);
		/*
		File textFile = new File(tempFilePath +"SampleText.txt"); // fahrplan_at_tennet_scheduling_eu.cer
		String zipData = "Gzip compress a single file, and the Tar is collecting files into one archive file";
		org.apache.commons.io.FileUtils.writeByteArrayToFile(textFile, zipData.getBytes());
		
		//compressCommons( IOUtils.toInputStream(zipData), null, new FileOutputStream(zipFile_SMTP));
		compressCommons( new FileInputStream( textFile ), textFile.getName(), new FileOutputStream( zipFile_SMTP ) );
		*/
		
		FileInputStream fileInputStream = new FileInputStream( zipFile_SMTP );
		HashMap<String, ByteArrayOutputStream> uncompressedGZIPBytes = unCompressCommons( fileInputStream );
		System.out.println("Map:"+ uncompressedGZIPBytes);
		
		
		/*
		// String to Bytes
		byte[] byteStream = zipData.getBytes();
		System.out.println("String Data:"+ new String(byteStream, "UTF-8"));
		
		// Bytes to Compressed-Bytes then to String.
		byte[] gzipCompress = gzipCompress(byteStream);
		String gzipCompressString = new String(gzipCompress, "UTF-8");
		System.out.println("GZIP Compressed Data:"+ gzipCompressString);
		
		// Bytes to DeCompressed-Bytes then to String.
		byte[] gzipDecompress = gzipDecompress(gzipCompress);
		String gzipDecompressString = new String(gzipDecompress, "UTF-8");
		System.out.println("GZIP Decompressed Data:"+ gzipDecompressString);
		
		// https://stackoverflow.com/a/4350109/5081877
		
		org.apache.commons.io.FileUtils.writeByteArrayToFile(textFile, byteStream);
		
		
		//org.apache.commons.io.FileUtils.writeByteArrayToFile(zipFile, gzipCompress);
		//org.apache.commons.io.FileUtils.writeByteArrayToFile(zipFile, IOUtils.toByteArray( new FileInputStream(textFile) ));
		//compressGzip( Paths.get( textFile.getAbsolutePath() ),  Paths.get( zipFile.getAbsolutePath() ));
		compressCommons( IOUtils.toInputStream(zipData), null, new FileOutputStream(zipFile_SMTP));
		//compressCommons(new FileInputStream( textFile ), textFile.getName(), new FileOutputStream(zipFile));
		
		HashMap<String, ByteArrayOutputStream> uncompressedGZIPBytes = unCompressCommons( new FileInputStream( zipFile_SMTP ) );
		//HashMap<String, Object> uncompressedGZIPBytes = getUncompressedGZIPBytes( new FileInputStream( zipFile_SMTP ) );
		System.out.println("Map:"+ uncompressedGZIPBytes);
		
		boolean gzipWithStringBytes = false;
		if (gzipWithStringBytes) {
			FileInputStream inStream = new FileInputStream( zipFile_SMTP );
			byte[] fileGZIPBytes = getStreamBytes(inStream);
			byte[] gzipFileDecompress = gzipDecompress(fileGZIPBytes);
			System.out.println("GZIP Decompressed Data:"+ new String(gzipFileDecompress, "UTF-8"));
		}
		
		//byte[] readFileToString =
				//org.apache.commons.io.FileUtils.readFileToByteArray(zipFile_SMTP);
				//org.apache.commons.io.IOUtils.toByteArray( new FileInputStream(zipFile_SMTP));
		//System.out.println("readFileToString :"+ new String(readFileToString, "UTF-8") );
		 */
		
		/*
		String archiveName = new SimpleDateFormat("yyyyMMddhhmm'.tar.gz'").format(new Date());
		System.out.println("Archive Name:"+archiveName); // 202106140659.tar.gz
		
		//  - tempFilePath+"commons";
		String dirPath = tempFilePath+"commons";
		File dir = new File(dirPath);
		if (dir.isDirectory()) System.out.println("File denoted by this abstract pathname is a directory");
		*/
	}
	
	public static byte[] getStreamBytes(InputStream inStream) throws IOException {
		return org.apache.commons.io.IOUtils.toByteArray(inStream);
	}
	public static HashMap<String, Object> getUncompressedGZIPBytes(InputStream gzipStream) throws IOException {
		HashMap<String, Object> gzipContent = new HashMap<String, Object>();
		/*
		boolean compressedFilename = GzipUtils.isCompressedFilename( zipFile_SMTP.getAbsolutePath());
		if (compressedFilename) {
			String filename = GzipUtils.getUncompressedFilename(AttachementFile);
			System.out.println("GZIP file name :"+filename);
		}*/
		
		List<InputStream> StreamCopy = multiplyBytes(gzipStream, 2);
		
		GzipCompressorInputStream gcis = new GzipCompressorInputStream( StreamCopy.get(0) );
		String filename = gcis.getMetaData().getFilename();
		System.out.println("GZIP File name :"+filename);
		
		byte[] fileGZIPBytes = getStreamBytes( StreamCopy.get(1) );
		if (filename == null) {
			
			byte[] gzipFileDecompress = gzipDecompress(fileGZIPBytes);
			String stringUncompressed = new String(gzipFileDecompress, "UTF-8");
			System.out.println("GZIP Decompressed String Data:"+ stringUncompressed);
			
			gzipContent.put("Bytes", stringUncompressed);
		} else {
			byte[] gzipDecompress_File = gzipDecompress( fileGZIPBytes );
			org.apache.commons.io.FileUtils.writeByteArrayToFile(new File( tempFilePath+filename ), gzipDecompress_File);
			
			//String gzipDecompressAsString = gzipDecompressAsString(fileGZIPBytes);
			//org.apache.commons.io.FileUtils.writeStringToFile(new File( tempFilePath+filename ), gzipDecompressAsString);
			gzipContent.put(filename, gzipDecompress_File);
		}
		
		return gzipContent;
	}
	
	public static void compressStringToGzip(String data, Path gzipFile) throws IOException {
		// org.apache.commons.io.FileUtils.writeByteArrayToFile(textFile, byteStream);
		try (
			GZIPOutputStream gos = new GZIPOutputStream(
								new FileOutputStream(gzipFile.toFile()))) {
			gos.write( data.getBytes( StandardCharsets.UTF_8 ) );
			
		}
	}
	
	
	// GZIP from Plain Bytes get compressed Bytes. - https://stackoverflow.com/a/44922240/5081877
	
	// Compress String to Gzip - With out any File name
	public static byte[] gzipCompress(byte[] uncompressedData) {
		byte[] result = new byte[]{};
		try (
			ByteArrayOutputStream bos = new ByteArrayOutputStream(uncompressedData.length);
			GZIPOutputStream gzipOS = new GZIPOutputStream(bos)
			) {
			gzipOS.write(uncompressedData);
			gzipOS.close(); // You need to close it before using ByteArrayOutputStream
			result = bos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}
	public static byte[] gzipDecompress(byte[] compressedData) {
		byte[] result = new byte[]{};
		try (
			ByteArrayInputStream bis = new ByteArrayInputStream(compressedData);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			GZIPInputStream gzipIS = new GZIPInputStream(bis)
			) {
			
			//String gZipString= IOUtils.toString(gzipIS);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = gzipIS.read(buffer)) != -1) {
				bos.write(buffer, 0, len);
			}
			result = bos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	// Stream Copy
	public static List<InputStream> multiplyBytes(InputStream input, int cloneCount) throws IOException {
		List<InputStream> copies = new ArrayList<InputStream>();
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		copy(input, baos);
		
		for (int i = 0; i < cloneCount; i++) {
			copies.add(new ByteArrayInputStream(baos.toByteArray()));
		}
		return copies;
	}
	public static void copy(InputStream in, OutputStream out) throws IOException {
		try {
			byte[] buffer = new byte[1024];
			int nrOfBytes = -1;
			while ((nrOfBytes = in.read(buffer)) != -1) {
				out.write(buffer, 0, nrOfBytes);
			}
			out.flush();
		} finally {
			close(in);
			close(out);
		}
	}
	public static void close(Closeable resource) {
		if (resource != null) {
			try {
				resource.close();
			} catch (IOException e) {
				System.err.println(e);
			}
		}
	}
}
