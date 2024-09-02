package service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import model.Poll;
import org.bson.types.ObjectId;
import org.jboss.logging.Logger;

@ApplicationScoped
public class PollsServicePlus {

    @Inject
    DigitalSignatureService digitalSignatureService;

    @Inject
    Logger logger;

    public void vote(String pollId, String username, String option, String signature) throws Exception {
        Poll poll = Poll.findById(new ObjectId(pollId));
        if (poll == null) {
            throw new NotFoundException("Poll not found");
        }

        if (!digitalSignatureService.verifySignature(username, option, signature)) {
            throw new SecurityException("Invalid signature");
        }

        poll.votes.merge(option, 1, Integer::sum);

        poll.update();
        logger.info("Vote placed in poll");

    }
}
