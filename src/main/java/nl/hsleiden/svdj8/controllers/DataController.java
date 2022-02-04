package nl.hsleiden.svdj8.controllers;

import nl.hsleiden.svdj8.models.Data;
import nl.hsleiden.svdj8.services.DeconstructService;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DataController {
    private static DataController dataController;

    DeconstructService deconstructService;

    public static DataController getInstance() {
        if (dataController == null) {
            dataController = new DataController();
        }
        return dataController;
    }

    public Data convertToNewData(Data oldData) {
        return null;
    }

    public Map<String, Object> deconstructOldData(String json) {
        return deconstructService.deconstructJson(json);
    }

    public Data reconstructOldData(Data oldData) {
        return null;
    }

    private void isNewData(Boolean isNewData) {

    }

    private void setDutyToDone(String done) {

    }

    public ArrayList<Data> getAllData() {
        return null;
    }

    public Data getData() {
        return null;
    }

    public Data setData(Map<String, Object> mapData) {
        String token = (String) mapData.get("token");
        char duty = (char) mapData.get("duty");
        HashMap<String, Object> givenVariables = (HashMap<String, Object>) mapData.get("givenVariables");
        return new Data(token, duty, givenVariables);
    }


}
