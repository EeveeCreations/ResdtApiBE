package nl.hsleiden.svdj8.models.tables;

import org.springframework.lang.Nullable;

import javax.persistence.*;

@Entity
@Table(name = "answer")
public class Answer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @SequenceGenerator(name = "id_Sequence", sequenceName = "ID_SEQ")
    @Column(name = "answer_id")
    private Long answerID;

    @Column(name = "answer_text")
    private String answerText;

    @Column(name = "question_id")
    private Long parentQuestionID;

    @Nullable
    @OneToOne(targetEntity = Question.class)
    @JoinColumn(name = "next_question_id", referencedColumnName = "question_id")
    private Question nextQuestionID;

    @Nullable
    @OneToOne(targetEntity = Advice.class)
    @JoinColumn(name = "advice_id", referencedColumnName = "advice_id")
    private Advice advice;

    public Answer(java.lang.Long answerID, String answerText) {
        this.answerID = answerID;
        this.answerText = answerText;
    }

    public Answer() {

    }

    public java.lang.Long getAnswerID() {
        return answerID;
    }

    public void setAnswerID(java.lang.Long answerID) {
        this.answerID = answerID;
    }

    public java.lang.Long getParentQuestionID() {
        return parentQuestionID;
    }

    public void setParentQuestionID(java.lang.Long parentLongID) {
        this.parentQuestionID = parentLongID;
    }

    public String getAnswerText() {
        return answerText;
    }

    public void setAnswerText(String answerText) {
        this.answerText = answerText;
    }

    public Question getNextQuestion() {
        return nextQuestionID;
    }

    public void setNextQuestion(Question nextQuestion) {
        this.nextQuestionID = nextQuestion;
    }

    @Nullable
    public Advice getAdvice() {
        return advice;
    }

    public void setAdvice(@Nullable Advice advice) {
        this.advice = advice;
    }
}
