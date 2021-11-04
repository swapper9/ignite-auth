package ru.swap.server.security.permissions;

import lombok.Data;
import org.apache.ignite.plugin.security.SecurityPermission;

import java.io.Serializable;
import java.util.List;

@Data
public class SystemPermission implements Serializable {
    private List<SecurityPermission> securityPermissions;
}
