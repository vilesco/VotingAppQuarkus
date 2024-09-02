package model;

import io.quarkus.mongodb.panache.PanacheMongoEntity;
import io.quarkus.mongodb.panache.common.MongoEntity;

import java.util.*;

@MongoEntity(collection = "polls")
public class Poll extends PanacheMongoEntity {
    public String question;
    public List<String> options;
    public Map<String, Integer> votes = new HashMap<>();
    public Set<String> usersVoted = new HashSet<>();

    public boolean hasUserVoted(String username) {
        return usersVoted.contains(username);
    }

    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public List<String> getOptions() {
        return options;
    }

    public void setOptions(List<String> options) {
        this.options = options;
    }

    public Map<String, Integer> getVotes() {
        return votes;
    }

    public void setVotes(Map<String, Integer> votes) {
        this.votes = votes;
    }
}