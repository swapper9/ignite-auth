package ru.swap.server.security.permissions;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class Subject implements Serializable {
    private String login;
    private List<ServicePermission> servicePermissions;
    private List<SystemPermission> systemPermissions;
    private List<CachePermission> cachePermissions;
    private List<TaskPermission> taskPermissions;
}
