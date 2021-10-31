package ru.swap.remote;

import org.apache.ignite.Ignition;
import org.apache.ignite.client.IgniteClient;
import org.apache.ignite.configuration.ClientConfiguration;
import ru.swap.server.service.GridService;
import ru.swap.server.entity.User;

import java.util.ArrayList;
import java.util.List;

public class ThinClientGetUsers {

    public static void main(String[] args) throws Exception {

        ClientConfiguration cfg = new ClientConfiguration().setAddresses("127.0.0.1:10800");
        try (IgniteClient client = Ignition.startClient(cfg)) {

            GridService gridService = client.services().serviceProxy(GridService.SERVICE_NAME, GridService.class, 1000);

            List<User> userList = new ArrayList<>();
            long id = 1;
            while (id < 100) {
                userList.add(gridService.getUser(id++));
            }
            System.out.println("Generated users:");
            userList.forEach(System.out::println);

        }
    }
}
