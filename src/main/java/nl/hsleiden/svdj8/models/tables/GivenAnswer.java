package nl.hsleiden.svdj8.models.tables;

import javax.persistence.*;

@Entity
@Table(name = "given_answer")
public class GivenAnswer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "given_answer_id")
    private Long givenAnswerID;

    @Column(name = "elapsed_seconds")
    private int elapsedSeconds;


    @Column(name = "route_id")
    private long routeID;

    @OneToOne(targetEntity = Question.class)
    @JoinColumn(name = "question_id", referencedColumnName = "question_id")
    private Question question;

    @OneToOne(targetEntity = Answer.class)
    @JoinColumn(name = "answer_id", referencedColumnName = "answer_id")
    private Answer answer;

    public GivenAnswer(Long givenAnswerID, int elapsedSeconds, Answer answer) {
        this.givenAnswerID = givenAnswerID;
        this.elapsedSeconds = elapsedSeconds;
        this.answer = answer;
    }

    public GivenAnswer() {
    }

    public Long getGivenAnswerID() {
        return givenAnswerID;
    }

    public void setGivenAnswerID(Long givenAnswerId) {
        this.givenAnswerID = givenAnswerId;
    }

    public int getElapsedSeconds() {
        return elapsedSeconds;
    }

    public void setElapsedSeconds(int elapsedSeconds) {
        this.elapsedSeconds = elapsedSeconds;
    }

    public Question getQuestion() {
        return question;
    }

    public void setQuestion(Question question) {
        this.question = question;
    }

    public Answer getAnswer() {
        return answer;
    }

    public void setAnswer(Answer answer) {
        this.answer = answer;
    }

    public long getRouteId() {
        return routeID;
    }

    public void setRouteId(long routeId) {
        this.routeID = routeId;
    }

}
