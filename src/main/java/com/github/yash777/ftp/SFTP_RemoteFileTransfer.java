package com.github.yash777.ftp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class SFTP_RemoteFileTransfer {
	private static final Log log = LogFactory.getLog(SFTP_RemoteFileTransfer.class);
	
	// https://www.ghacks.net/2019/07/29/how-to-setup-an-sftp-server-in-windows-using-openssh/
	static String sftpHost, sftpUsername, sftpPassword;
	static int sftpPort;

	// 1=fame-sftp.ud01.f-001.net, 2=22, 3=UD01\W9097, 4=2020+Power-Dispatch, 5=/DFSRoot34000/SPECIAL/TRADING/PowerOps/Schedules/TSO declaration/
	static {
		sftpHost = "fame-sftp.ud01.f-001.net";
		sftpPort = 22;
		sftpUsername = "UD01\\V7913";
		sftpPassword = "Worldmap@2021";
		
		/*sftpHost = "fame-sftp.ud01.f-001.net";
		sftpPort = 22;
		sftpUsername = "UD01\\W9097";
		sftpPassword = "2020+Power-Dispatch";*/
	}
	
	// https://mvnrepository.com/artifact/com.jcraft/jsch/0.1.54
	public static void main(String[] args) throws Exception {
		
		
		String NewFilePath = "C:/Yash/SFTPTransferTest.txt";
		File newFile = new File(NewFilePath);
		InputStream fileContent = new FileInputStream(newFile);
		String newFileName = newFile.getName();
		
		/*String destinationDir = "C:/Yash/Workplace SVN Branches/NeonDashboard/RemoteFile",
			archivalDir = "C:/Yash/Workplace SVN Branches/NeonDashboard/RemoteFile/BackUP";*/
		
		String destinationDir = "/K-Drive (u-dfs)/Uniper/UIT/PROJECTS/Neon/CR123/", archivalDir = null;
		//String destinationDir = "/DFSRoot34000/SPECIAL/TRADING/PowerOps/Schedules/TSO declaration/", archivalDir = null;
		
		copyReportToDestination(fileContent, newFileName, destinationDir, archivalDir);
	}
	
	public static void copyReportToDestination(InputStream fileContent, String fileName, String destinationDir,
			String archivalDir) 
					throws Exception{
		Session session = null;
		Channel channel = null;
		ChannelSftp channelSftp = null;

		try {
			JSch jsch = new JSch();
			session = jsch.getSession(sftpUsername, sftpHost, sftpPort);
			session.setPassword(sftpPassword);
			
			java.util.Properties config = new java.util.Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);
			session.connect();
			channel = session.openChannel("sftp");
			channel.connect();
			channelSftp = (ChannelSftp) channel;
			channelSftp.cd(destinationDir);
			
			// Move old reports to archive location
			if(archivalDir != null)
				moveExistingFilesToArchive(channelSftp, destinationDir, archivalDir);
			
			// copy new report to destination directory
			copyReportsToDestination(channelSftp, fileContent, fileName, destinationDir);
			
			channel.disconnect();
			session.disconnect();
			if (session.isConnected()) {
				session.disconnect();
			}
		} catch (JSchException|SftpException e) {
			throw new Exception("Failed while transfering file and caught Exception!:"+ e);
		}
	}

	public static void moveExistingFilesToArchive(ChannelSftp channelSftp, String sftpWorkingDir, String destinationDir) throws Exception {
		try {
			Vector<ChannelSftp.LsEntry> filesList = channelSftp.ls("*.*");
			log.info("filesList size:" + filesList.size());
			if (!filesList.isEmpty()) {
				for (ChannelSftp.LsEntry entry : filesList) {
					String filename = entry.getFilename();
					log.info("Filename::" + filename);
					String localFile = sftpWorkingDir + "/" + filename;
					String archivalFilename = filename;
					String[] parts = null;
					if (filename.contains(".")) { // filename.matches("\\*.\\*")
						log.info("File name change");
						parts = filename.split("\\.");
						// ArchivalTimestamp to be appended to filename
						String timeStamp = new SimpleDateFormat("yyyyMMdd_HH_mm_ss").format(new Date());
						archivalFilename = parts[0] + "_" + timeStamp + "." + parts[1];
					}
					String remoteDir = destinationDir + "/" + archivalFilename;
					log.info("Ready for transfer" + remoteDir + "\n" + localFile);
					channelSftp.cd(destinationDir);
					channelSftp.rename(localFile, remoteDir);
					channelSftp.cd(sftpWorkingDir);
				}
			}
		} catch (SftpException e) {
			throw new Exception("Failed while transfering file and caught SftpException!:"+ e);
		}
	}

	public static void copyReportsToDestination(ChannelSftp channelSftp, InputStream fileContent, String fileName, String destinationDir) throws Exception {
		try {
			channelSftp.cd(destinationDir);
			log.info("Report upload to Remote directory Starts");
			channelSftp.put(fileContent, destinationDir+"/"+fileName);
			fileContent.close();
			log.info("File uploaded successfully - "+ destinationDir);
		} catch(SftpException|IOException e) {
			throw new Exception("Failed while transfering file and caught Exception!:"+ e);
		}
	}
}