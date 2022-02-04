package nl.hsleiden.svdj8.daos;

import nl.hsleiden.svdj8.models.tables.Route;
import nl.hsleiden.svdj8.repository.RouteRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class RouteDAO {

    @Autowired
    private RouteRepository routeRepository;

    public RouteDAO(RouteRepository routeRepository) {
        this.routeRepository = routeRepository;
    }

    public List<Route> getAll() {
        ArrayList<Route> routes = (ArrayList<Route>) this.routeRepository.findAll();
        routes.sort(Comparator.comparingLong(Route::getRouteID));
        return routes;
    }

    public Route getById(long id) {
        Optional<Route> optionalRoute = routeRepository.findById(id);
        if(optionalRoute.isEmpty()){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Route with the id: " + id + " not found");
        }
        return optionalRoute.get();
    }


    public Optional<Route> getByIdOptional(long id) {
        Optional<Route> optionalRoute = routeRepository.findById(id);
        return optionalRoute;
    }

    public void deleteRoute(long id) {
        routeRepository.deleteById(id);
    }

    public Route addRoute(Route newRoute) {
        return routeRepository.save(newRoute);
    }
}
