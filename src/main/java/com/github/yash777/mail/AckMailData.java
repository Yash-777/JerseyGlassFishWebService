package com.github.yash777.mail;

import java.io.InputStream;
import java.io.Reader;
import java.util.Date;

public class AckMailData
{
	private String from;
	
	@Override
	public String toString() {
		return "AckMailData [from=" + from + ", to=" + to + ", mailDate=" + mailDate + ", subject=" + subject
				+ ", body=" + body + ", attachmentName=" + attachmentName //+ ", attachmentData=" + attachmentData
				+ ", fpId=" + fpId + ", httpDetail=" + httpDetail + ", attachmentDataStream=" + attachmentDataStream
				+ "]";
	}

	private String to;
	private String mailDate;
	private String subject;
	private String body;
	private String attachmentName;
	//private Reader attachmentData;
	private String fpId;
	private String httpDetail;
	
	private InputStream attachmentDataStream;
	public InputStream getAttachmentDataStream() {
		return attachmentDataStream;
	}
	public void setAttachmentDataStream(InputStream attachmentDataStream) {
		this.attachmentDataStream = attachmentDataStream;
	}
	
	public String getFrom()
	{
		return from;
	}

	public void setFrom(String from)
	{
		this.from = from;
	}

	public String getTo()
	{
		return to;
	}

	public void setTo(String to)
	{
		this.to = to;
	}

	public String getMailDate()
	{
		return mailDate;
	}

	public void setMailDate(String mailDate)
	{
		this.mailDate = mailDate;
	}

	public String getSubject()
	{
		return subject;
	}

	public void setSubject(String subject)
	{
		this.subject = subject;
	}

	public String getBody()
	{
		return body;
	}

	public void setBody(String body)
	{
		this.body = body;
	}

	public String getAttachmentName()
	{
		return attachmentName;
	}

	public void setAttachmentName(String attachmentName)
	{
		this.attachmentName = attachmentName;
	}

	/*public Reader getAttachmentData()
	{
		return attachmentData;
	}

	public void setAttachmentData(Reader attachmentData)
	{
		this.attachmentData = attachmentData;
	}*/

	public String getFpId()
	{
		return fpId;
	}

	public void setFpId(String fpId)
	{
		this.fpId = fpId;
	}

	public String getHttpDetail()
	{
		return httpDetail;
	}

	public void setHttpDetail(String httpDetail)
	{
		this.httpDetail = httpDetail;
	}

}