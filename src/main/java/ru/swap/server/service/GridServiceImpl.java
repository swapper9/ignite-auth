package ru.swap.server.service;

import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.resources.IgniteInstanceResource;
import org.apache.ignite.services.ServiceContext;
import ru.swap.server.entity.Permission;
import ru.swap.server.entity.User;

public class GridServiceImpl implements GridService {

    @IgniteInstanceResource
    private Ignite ignite;

    private IgniteCache<Long, User> userCache;
    private IgniteCache<Long, Permission> permissionCache;

    @Override
    public void cancel(ServiceContext serviceContext) {

    }

    @Override
    public void init(ServiceContext serviceContext) throws Exception {
        userCache = ignite.cache("userCache");
        permissionCache = ignite.cache("permissionCache");
    }

    @Override
    public void execute(ServiceContext serviceContext) throws Exception {

    }

    @Override
    public User getUser(Long userId) {
        return userCache.get(userId);
    }

    @Override
    public void putUser(Long userId, User user) {
        userCache.put(userId, user);
    }

    @Override
    public Permission getPermission(Long permissionId) {
        return permissionCache.get(permissionId);
    }

    @Override
    public void putPermission(Long permissionId, Permission permission) {
        permissionCache.put(permissionId, permission);
    }
}
