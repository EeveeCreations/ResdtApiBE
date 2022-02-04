package nl.hsleiden.svdj8.models.tables;

import java.util.Set;

import javax.persistence.*;
import java.util.HashSet;

@Entity
@Table(name = "advice")
public class Advice {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "advice_id")
    private Long adviceID;

    @ManyToMany
    @JoinTable(
            name = "grant_and_advice",
            joinColumns = @JoinColumn(name = "advice_id"),
            inverseJoinColumns = @JoinColumn(name = "grant_id")
    )
    Set<Grant> grants = new HashSet<>();

    private String name;
    private String description;

    public Advice(Long adviceID, String name, String description) {
        this.adviceID = adviceID;
        this.name = name;
        this.description = description;
    }

    public Advice() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setAdviceID(Long adviceID) {
        this.adviceID = adviceID;
    }

    public Long getAdviceID() {
        return adviceID;
    }

    public Set<Grant> getGrants() {
        return grants;
    }

    public void setGrants(Set<Grant> grants) {
        this.grants = grants;
    }
}
