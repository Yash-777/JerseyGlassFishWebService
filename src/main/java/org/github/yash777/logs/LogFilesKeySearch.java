package org.github.yash777.logs;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class LogFilesKeySearch {
	private static final Log log = LogFactory.getLog(LogFilesKeySearch.class);
	static String fileExtension = ".txt";
	
	static List<String> skipFiles = new ArrayList<String>();
	static {
		skipFiles.add(".classpath");// .project, stackexchangeSSL.cer
		skipFiles.add(".project");
		skipFiles.add("stackexchangeSSL.cer");
		skipFiles.add("pom.xml");
	}
	public static void main(String[] args) throws FileNotFoundException {
		//File dirChangeExtensions = new File("C:\\Yash\\Logs");
		//changeFileName(dirChangeExtensions); // https://stackoverflow.com/a/22502212/5081877
		
		String absolutePath = "./"; // Same Project wiki file search // C:\\Yash\\Logs
		File dir = new File(absolutePath);
		String serchKey = "jersey-quickstart-webapp";
				//"java.sql.SQLTimeoutException: ORA-01013";
		
		List<String> searchFiles = searchFiles(dir, serchKey, null); // https://stackoverflow.com/a/13859481/5081877
		for (String fileContainsStr : searchFiles) {
			System.out.println("File Contains: "+fileContainsStr);
			log.info("File Contains Log Key: "+fileContainsStr);
		}
	}
	public static void changeFileName(File dir) {
		// change file names in 'Directory':
		String absolutePath = dir.getAbsolutePath();
		File[] filesInDir = dir.listFiles();
		//int i = 0;
		for(File file:filesInDir) {
			if (file.isFile()) {
				//i++;
				String fileName = file.getName();
				if (fileName.endsWith(fileExtension)) {
					//System.out.println("File: "+absolutePath+"/"+name);
				} else if (!skipFiles.contains(fileName)) {
					String newName =  fileName+fileExtension; //"my_file_" + i + ".pdf";
					String newPath = absolutePath + "\\" + newName;
					file.renameTo(new File(newPath));
					System.out.println("Path:"+absolutePath +", File:"+ fileName + " changed to:" + newName);
				}
				
			} else if (file.isDirectory()) {
				System.out.println("Folder: "+absolutePath);
				//changeFileName(file);
			}
		}
	}
	
	static List<String> searchFiles(File dir, String pattern, List<String> result) throws FileNotFoundException {
		if (!dir.isDirectory()) {
			throw new IllegalArgumentException("file has to be a directory");
		}

		if (result == null) {
			result = new ArrayList<String>();
		}

		File[] files = dir.listFiles();

		if (files != null) {
			for (File currentFile : files) {
				if (currentFile.isDirectory()) {
					searchFiles(currentFile, pattern, result);
				} else {
					Scanner scanner = new Scanner(currentFile);
					String stringMatchedWithPattern = scanner.findWithinHorizon(pattern, 0);// "horizon=0" will scan beyond the line bound
					if (stringMatchedWithPattern != null) {
						System.out.println("File Name:"+currentFile.getName());
						//System.out.println(stringMatchedWithPattern);
						result.add(currentFile.getName());
					}
					scanner.close();
				}
			}
		}
		return result;
	}
}
