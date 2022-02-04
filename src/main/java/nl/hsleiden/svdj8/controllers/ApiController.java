package nl.hsleiden.svdj8.controllers;

import nl.hsleiden.svdj8.models.Data;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ApiController {

    private static ApiController apiController;

    public static ApiController getInstance() {
        if(apiController == null) {
            apiController = new ApiController();
        }
        return apiController;
    }

    public boolean newRequest(String json) {
        Data incomingData = deconstructData(json);
        return checkStatement(incomingData);
    }

    public Data deconstructData(String json) {
        DataController dataController = DataController.getInstance();

        Map<String, Object> deconstructedData = dataController.deconstructOldData(json);
        return dataController.setData(deconstructedData);
    }

    private Boolean checkStatement(Data data) {
        StatementController statementController = StatementController.getInstance();
        char statement = data.getDuty();
        switch (statement) {
            case 'C':
                return statementController.getCreateStatement(data);
            case 'R':
                return statementController.getReadDataStatement(data);
            case 'U':
                return statementController.getUpdateStatement(data);
            case 'D':
                return statementController.getDeleteStatement(data);
            default:
                return null;
        }
    }

}
