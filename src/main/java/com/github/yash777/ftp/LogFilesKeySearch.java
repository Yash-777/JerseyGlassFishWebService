package com.github.yash777.ftp;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class LogFilesKeySearch {

	static String fileExtension = ".txt"; // MyApp-DEV.log.1 to MyApp-DEV.log.1.txt

	public static void main(String[] args) throws FileNotFoundException {
		String absolutePath = "C:\\Yash\\WebServer\\Logs";
		File dir = new File(absolutePath);
		
		changeFileName(dir); // https://stackoverflow.com/a/22502212/5081877
		
		String serchKey = "java.sql.SQLTimeoutException: ORA-01013";
		
		List<String> searchFiles = searchFiles(dir, serchKey, null); // https://stackoverflow.com/a/13859481/5081877
		for (String fileContainsStr : searchFiles) {
			System.out.println("File Contains: " + fileContainsStr);
		}
	}

	public static void changeFileName(File dir) {
		// change file names in 'Directory':
		String absolutePath = dir.getAbsolutePath();
		File[] filesInDir = dir.listFiles();
		// int i = 0;
		for (File file : filesInDir) {
			if (file.isFile()) {
				// i++;
				String name = file.getName();
				if (name.endsWith(fileExtension)) {
					// System.out.println("File: "+absolutePath+"/"+name);
				} else {
					String newName = name + fileExtension; // "my_file_" + i + ".pdf";
					String newPath = absolutePath + "\\" + newName;
					file.renameTo(new File(newPath));
					System.out.println("Path:" + absolutePath + ", File:" + name + " changed to:" + newName);
				}
			} else if (file.isDirectory()) {
				System.out.println("Folder: " + absolutePath);
				// changeFileName(file);
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
					String stringMatchedWithPattern = scanner.findWithinHorizon(pattern, 0);
					// "horizon=0" will scan beyond the line bound
					if (stringMatchedWithPattern != null) {
						System.out.println("File Name:" + currentFile.getName());
						// System.out.println(stringMatchedWithPattern);
						result.add(currentFile.getName());
					}
					scanner.close();
				}
			}
		}
		return result;
	}
}