package nl.hsleiden.svdj8.models.tables;

import javax.persistence.*;

@Entity
@Table(name = "grant")
public class Grant {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "grant_id")
    private Long grantID;

    private String name;
    private String description;
    private String grant_link;

    public Grant(Long grantID, String name, String description, String grant_link) {
        this.grantID = grantID;
        this.name = name;
        this.description = description;
        this.grant_link = grant_link;
    }

    public Grant() {
    }


    public void setGrantID(Long grantID) {
        this.grantID = grantID;
    }

    public Long getGrantID() {
        return grantID;
    }

    public String getName() {
        return name;
    }

    public void setName(String nameGrant) {
        this.name = nameGrant;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getGrant_link() {
        return grant_link;
    }

    public void setGrant_link(String grant_link) {
        this.grant_link = grant_link;
    }
}
