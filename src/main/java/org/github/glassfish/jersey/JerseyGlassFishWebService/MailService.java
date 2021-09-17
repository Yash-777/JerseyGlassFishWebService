package org.github.glassfish.jersey.JerseyGlassFishWebService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.github.yash777.mail.SMTP_MailSend;

@Path("/mail")
public class MailService {
	// http://localhost:8080/JerseyGlassFishWebService/jersey2/glassfish/mail/true/true?storedMessage=false&isCompressedGZIP=true
	@GET
	@Path("/{signed}/{encrypted}")
	public Response sayHello_PathParam(@PathParam("signed") String signed, @PathParam("encrypted") String encrypted,
			@QueryParam("storedMessage") String storedMessage,
			@QueryParam("isCompressedGZIP") String isCompressedGZIP) {
		
		System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> /mail/signed/encrypted ");
		boolean signed2 = Boolean.valueOf(signed);
		boolean encrypted2 = Boolean.valueOf(encrypted);
		boolean storedMessage2 = Boolean.valueOf(storedMessage);
		boolean isCompressedGZIP2 = Boolean.valueOf(isCompressedGZIP);
		String inputs = "signed:" + signed + ", encrypted:" + encrypted + ", storedMessage:" + storedMessage
				+ ", isCompressedGZIP:" + isCompressedGZIP;
		
		SMTP_MailSend obj = new SMTP_MailSend(signed2, encrypted2, storedMessage2, isCompressedGZIP2);
		try {
			obj.mailSend();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return Response.status(200).entity("Inputs : " + inputs).build();
	}
}