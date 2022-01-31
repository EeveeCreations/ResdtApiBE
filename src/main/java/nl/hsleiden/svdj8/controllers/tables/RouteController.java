package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.RouteDAO;
import nl.hsleiden.svdj8.models.tables.Route;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class RouteController {

    @Autowired
    public final RouteDAO routeDAO;

    public RouteController(RouteDAO routeDAO) {
        this.routeDAO = routeDAO;
    }

    @GetMapping(value = "/route/all")
    public List<Route> getAllRoutes() {
        return routeDAO.getAll();
    }

    @GetMapping(value = "/route/{id}")
    public Route getRoute(@PathVariable final Long id) {
        return routeDAO.getById(id);
    }

    @PutMapping(value = "/route/{id}")
    public Route editRoute(@RequestBody Route editRoute, @PathVariable Long id) throws Exception {

        return routeDAO.getByIdOptional(id)
                .map(route -> {
                    route.setTotalTime(editRoute.getTotalTime());
                    route.setGivenAnswers(editRoute.getGivenAnswers());
                    return routeDAO.addRoute(route);
                })
                .orElseThrow(() -> new Exception(
                        "No route found with id " + id + "\""));
    }

    @PostMapping(value = "/route")
    public Route addRoute(@RequestBody Route newRoute) {
        return routeDAO.addRoute(newRoute);
    }

    @DeleteMapping("/route/{id}")
    public void deleteRoute(@PathVariable Long id) {
        routeDAO.deleteRoute(id);
    }


}
