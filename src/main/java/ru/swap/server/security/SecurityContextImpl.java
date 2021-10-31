package ru.swap.server.security;

import java.io.Serializable;
import java.util.Collection;

import org.apache.ignite.internal.processors.security.SecurityContext;
import org.apache.ignite.internal.util.typedef.F;
import org.apache.ignite.plugin.security.SecurityPermission;
import org.apache.ignite.plugin.security.SecuritySubject;


public class SecurityContextImpl implements SecurityContext, Serializable {

    private static final long serialVersionUID = -5299362655289651223L;

    private final SecuritySubject subject;

    public SecurityContextImpl(SecuritySubject subject) {
        this.subject = subject;
    }

    public SecuritySubject subject() {
        return subject;
    }

    public boolean taskOperationAllowed(String taskClsName, SecurityPermission perm) {
        return hasPermission(subject.permissions().taskPermissions().get(taskClsName), perm);
    }

    public boolean cacheOperationAllowed(String cacheName, SecurityPermission perm) {
        return hasPermission(subject.permissions().cachePermissions().get(cacheName), perm);
    }

    public boolean serviceOperationAllowed(String srvcName, SecurityPermission perm) {
        return hasPermission(subject.permissions().servicePermissions().get(srvcName), perm);
    }


    public boolean systemOperationAllowed(SecurityPermission perm) {
        Collection<SecurityPermission> perms = subject.permissions().systemPermissions();

        if (F.isEmpty(perms))
            return subject.permissions().defaultAllowAll();

        return perms.stream().anyMatch(p -> perm == p);
    }


    public boolean operationAllowed(String opName, SecurityPermission perm) {
        switch (perm) {
            case CACHE_CREATE:
            case CACHE_DESTROY:
                return systemOperationAllowed(perm) || cacheOperationAllowed(opName, perm);

            case CACHE_PUT:
            case CACHE_READ:
            case CACHE_REMOVE:
                return cacheOperationAllowed(opName, perm);

            case TASK_CANCEL:
            case TASK_EXECUTE:
                return taskOperationAllowed(opName, perm);

            case SERVICE_DEPLOY:
            case SERVICE_INVOKE:
            case SERVICE_CANCEL:
                return serviceOperationAllowed(opName, perm);

            case EVENTS_DISABLE:
            case EVENTS_ENABLE:
            case ADMIN_VIEW:
            case ADMIN_CACHE:
            case ADMIN_QUERY:
            case ADMIN_OPS:
            case JOIN_AS_SERVER:
                return systemOperationAllowed(perm);

            // You should decide what is a proper reaction when unknown permission is getting
            default:
                throw new IllegalArgumentException("Unknown security permission: " + perm);
        }
    }


    private boolean hasPermission(Collection<SecurityPermission> perms, SecurityPermission perm) {
        if (perms == null)
            return subject.permissions().defaultAllowAll();

        return perms.stream().anyMatch(p -> perm == p);
    }

}
