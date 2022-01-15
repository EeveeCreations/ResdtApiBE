package nl.hsleiden.svdj8.models.tables;

import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "question")
public class Question {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "question_id")
    private long questionID;

    @Column(name = "question_text")
    private String questionText;

    @OneToMany(mappedBy = "parentQuestionID", targetEntity = Answer.class)
    private List<Answer> answers = new ArrayList<>();

    @Column(name = "extra_info_tile")
    private String extraInfoTitle;

    @Column(name = "extra_info_description")
    private String extraInfoDescription;

    @Column(name = "extra_info_video_url")
    private String extraInfoVideoURL;

    public Question(java.lang.Long questionID, String questionText, String extraInfoTitle, String extraInfoDescription, String extraInfoVideoURL) {
        this.questionID = questionID;
        this.questionText = questionText;
        this.extraInfoTitle = extraInfoTitle;
        this.extraInfoDescription = extraInfoDescription;
        this.extraInfoVideoURL = extraInfoVideoURL;
    }

    public Question() {

    }

    public String getQuestionText() {
        return questionText;
    }

    public void setQuestionText(String questionText) {
        this.questionText = questionText;
    }

    public List<Answer> getAnswers() {
        return answers;
    }

    public void setAnswers(List<Answer> answers) {
        this.answers = answers;
    }

    public String getExtraInfoTitle() {
        return extraInfoTitle;
    }

    public void setExtraInfoTitle(String extraInfoTile) {
        this.extraInfoTitle = extraInfoTile;
    }

    public String getExtraInfoDescription() {
        return extraInfoDescription;
    }

    public void setExtraInfoDescription(String extraInfoDescription) {
        this.extraInfoDescription = extraInfoDescription;
    }

    public String getExtraInfoVideoURL() {
        return extraInfoVideoURL;
    }

    public void setExtraInfoVideoURL(String extraInfoVideoURL) {
        this.extraInfoVideoURL = extraInfoVideoURL;
    }

    public void setQuestionID(java.lang.Long questionID) {
        this.questionID = questionID;
    }

    public java.lang.Long getQuestionID() {
        return questionID;
    }

}