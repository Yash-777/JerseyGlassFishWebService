package org.github.glassfish.jersey.JerseyGlassFishWebService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/sayhello")
public class HelloWorldService {

	// http://localhost:8080/JerseyGlassFishWebService/jersey2/glassfish/sayhello/Yash
    @GET
    @Path("/{name}")
    public Response sayHello_PathParam(@PathParam("name") String msg) {
        String output = "Hello, " + msg + "!";
        return Response.status(200).entity(output).build();
    }

    // http://localhost:8080/JerseyGlassFishWebService/jersey2/glassfish/sayhello?name=Yash777
    @GET
    public Response sayHello_QueryParam(@QueryParam("name") String msg) {
        String output = "Hello, " + msg + "!";
        return Response.status(200).entity(output).build();
    }
    
    // http://localhost:8080/JerseyGlassFishWebService/jersey2/glassfish/sayhello/github/query?account2=stackoverflow
    @GET
    @Path("/{account}/query")
    public Response sayHello_PathQueryParam(@PathParam("account") String github, @QueryParam("account2") String stackOverflow) {
        String output = "Hello, Your Accouts lsit [" + github + " and "+stackOverflow+"]!";
        return Response.status(200).entity(output).build();
    }
}
