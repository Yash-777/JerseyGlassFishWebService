package org.github.glassfish.jersey.JerseyGlassFishWebService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

//import jakarta.ws.rs.GET;
//import jakarta.ws.rs.Path;
//import jakarta.ws.rs.Produces;
//import jakarta.ws.rs.core.MediaType;

/**
 * Root resource (exposed at "myresource" path)
 * 
 * https://howtodoinjava.com/jersey/jersey2-hello-world-example/
 * 
 * Jersey team, which developed Jersey 1.x, joined new organization GlassFish and all new upgrades are released under since 2.x.
 * It has changed a lot of things in framework functionalities. https://eclipse-ee4j.github.io/jersey/
 * 
 * 2.x :: provides support for JAX-RS APIs and serves as a JAX-RS (JSR 311 & JSR 339 & JSR 370) Reference Implementation.
 * 3.x :: provides support for Jakarta RESTful Web Services 3.0.
 */
@Path("myresource")
public class MyResource { // <url-pattern>/jersey2/glassfish/*</url-pattern>

    /**
     * Method handling HTTP GET requests. The returned object will be sent
     * to the client as "text/plain" media type.
     *
     * @return String that will be returned as a text/plain response.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getIt() {
        return "Got it!";
    }
    
    @GET
    @Path("/response")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getItResponse() {
        String output = "Got it!";
        return Response.status(200).entity(output).build();
    }
}
