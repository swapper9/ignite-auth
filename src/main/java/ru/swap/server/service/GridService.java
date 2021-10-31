package ru.swap.server.service;

import org.apache.ignite.services.Service;
import ru.swap.server.entity.Permission;
import ru.swap.server.entity.User;

public interface GridService extends Service {
    String SERVICE_NAME = "gridService";

    User getUser(Long userId);
    void putUser(Long userId, User user);
    Permission getPermission(Long permissionId);
    void putPermission(Long permissionId, Permission permission);
}
