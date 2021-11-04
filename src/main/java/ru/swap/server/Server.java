package ru.swap.server;

import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.Ignition;
import org.apache.ignite.services.ServiceConfiguration;
import ru.swap.server.entity.User;
import ru.swap.server.service.GridService;
import ru.swap.server.service.GridServiceImpl;

public class Server {

    public static void main(String[] args) {
        ServiceConfiguration serviceCfg = new ServiceConfiguration();
        serviceCfg.setName(GridService.SERVICE_NAME);
        serviceCfg.setMaxPerNodeCount(1);
        serviceCfg.setTotalCount(1);
        serviceCfg.setService(new GridServiceImpl());

        Ignite ignite = Ignition.start("config/ignite-config.xml");
        ignite.services().deploy(serviceCfg);

        //fill caches
        IgniteCache<Long, User> userCache = ignite.cache("userCache");
        long id = 1;
        while (id < 100) {
            userCache.put(id, new User(id, NameGenerator.getName()));
            id++;
        }
    }


}
