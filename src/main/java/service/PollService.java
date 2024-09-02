package service;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import model.Poll;
import model.VoteRequest;
import org.jboss.logging.Logger;

import java.util.List;
@Path("/polls")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PollService {

    @Inject
    Logger logger;

    @Inject
    PollsServicePlus pollsServicePlus;

    @Inject
    DigitalSignatureService digitalSignatureService;

    @POST
    @RolesAllowed("admin")
    public Response createPoll(@Valid Poll poll) {
        poll.persist();
        logger.info("New poll created: " + poll.question);
        return Response.status(Response.Status.CREATED).build();
    }

    @GET
    public List<Poll> getAllPolls() {
        logger.info("Fetching all polls");
        return Poll.listAll();
    }

    @POST
    @Path("/{id}/vote")
    @RolesAllowed("user")
    public Response vote(@PathParam("id") String pollId, VoteRequest voteRequest, @Context SecurityContext securityContext) {
        try {
            String username = securityContext.getUserPrincipal().getName();
            if (!digitalSignatureService.verifySignature(username, voteRequest.option, voteRequest.signature)) {
                throw new WebApplicationException("Invalid signature", Response.Status.BAD_REQUEST);
            }
            pollsServicePlus.vote(pollId, username, voteRequest.option, voteRequest.signature);
            return Response.ok().build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

}