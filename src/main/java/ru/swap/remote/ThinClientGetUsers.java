package ru.swap.remote;

import lombok.extern.log4j.Log4j2;
import org.apache.ignite.Ignition;
import org.apache.ignite.client.ClientAuthorizationException;
import org.apache.ignite.client.ClientCache;
import org.apache.ignite.client.IgniteClient;
import org.apache.ignite.configuration.ClientConfiguration;
import ru.swap.server.entity.User;

@Log4j2
public class ThinClientGetUsers {

    public static void main(String[] args) throws Exception {

        ClientConfiguration cfg = new ClientConfiguration()
                .setAddresses("127.0.0.1:10800")
                .setUserName("thin-client-permissions")
                .setUserPassword("pwd");
        try (IgniteClient client = Ignition.startClient(cfg)) {

            ClientCache<Long, User> userCache = client.cache("userCache");
            User user = userCache.get(2L);
            System.out.println(user);
            userCache.put(2L, new User(2L, "Altered Name"));
            user = userCache.get(2L);
            System.out.println(user);
        } catch (ClientAuthorizationException e) {
            log.error(e.getMessage());
        }
    }
}
