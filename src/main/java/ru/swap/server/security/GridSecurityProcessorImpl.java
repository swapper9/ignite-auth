package ru.swap.server.security;

import java.net.InetSocketAddress;
import java.security.AllPermission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Collection;
import java.util.PropertyPermission;
import java.util.UUID;

import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.cluster.ClusterNode;
import org.apache.ignite.internal.GridKernalContext;
import org.apache.ignite.internal.IgniteNodeAttributes;
import org.apache.ignite.internal.processors.GridProcessorAdapter;
import org.apache.ignite.internal.processors.security.GridSecurityProcessor;
import org.apache.ignite.internal.processors.security.SecurityContext;
import org.apache.ignite.internal.util.typedef.F;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.plugin.security.AuthenticationContext;
import org.apache.ignite.plugin.security.SecurityCredentials;
import org.apache.ignite.plugin.security.SecurityException;
import org.apache.ignite.plugin.security.SecurityPermission;
import org.apache.ignite.plugin.security.SecurityPermissionSet;
import org.apache.ignite.plugin.security.SecurityPermissionSetBuilder;
import org.apache.ignite.plugin.security.SecuritySubject;
import org.apache.ignite.plugin.security.SecuritySubjectType;

public class GridSecurityProcessorImpl extends GridProcessorAdapter implements GridSecurityProcessor {

    private final SecurityCredentials localNodeCredentials;

    public GridSecurityProcessorImpl(GridKernalContext ctx, SecurityCredentials cred) {
        super(ctx);
        localNodeCredentials = cred;
    }

    private SecurityPermissionSet getPermissionSet(Object login) {
        if (login.equals("user")) {
            return new SecurityPermissionSetBuilder()
                    .appendCachePermissions("userCache", SecurityPermission.CACHE_READ)
                    .build();
        }
        if (login.equals("owner")) {
            return new SecurityPermissionSetBuilder()
                    //.appendSystemPermissions(SecurityPermission.CACHE_READ,SecurityPermission.CACHE_PUT,SecurityPermission.CACHE_REMOVE)
                    .appendCachePermissions("userCache", SecurityPermission.CACHE_READ, SecurityPermission.CACHE_PUT, SecurityPermission.CACHE_REMOVE)
                    .build();
        }

        return SecurityPermissionSetBuilder.ALLOW_ALL;
    }

    private PermissionCollection getSandboxPermissions(Object login) {
        PermissionCollection res = new Permissions();
        if (login.equals("sandboxSubject"))
            res.add(new PropertyPermission("java.version", "read"));
        else
            res.add(new AllPermission());
        return res;
    }

    /**
     * Checking the credentials of the joining node
     * @param node
     * @param credentials
     * @return
     */
    @Override
    public SecurityContext authenticateNode(ClusterNode node, SecurityCredentials credentials) {
        // This is the place to check the credentials of the joining node.

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(node.id())
                .login(credentials.getLogin())
                .address(new InetSocketAddress(F.first(node.addresses()), 0))
                .type(SecuritySubjectType.REMOTE_NODE)
                .permissions(getPermissionSet(credentials.getLogin()))
                .sandboxPermissions(getSandboxPermissions(credentials.getLogin()));

        U.quiet(false, "[GridSecurityProcessorImpl] Authenticate node; " +
                "localNode=" + ctx.localNodeId() +
                ", authenticatedNode=" + node.id() +
                ", login=" + credentials.getLogin());

        return new SecurityContextImpl(subject);
    }

    /**
     * Checking the credentials of the thin client
     * @param context
     * @return
     */
    @Override
    public SecurityContext authenticate(AuthenticationContext context) {

        // This is the place to check the credentials of the thin client.

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(context.subjectId())
                .login(context.credentials().getLogin())
                .type(SecuritySubjectType.REMOTE_CLIENT)
                .permissions(getPermissionSet(context.credentials().getLogin()));

        SecurityContext res = new SecurityContextImpl(subject);

        ctx.grid().getOrCreateCache("thin_clients").put(subject.id(), res);

        U.quiet(false, "[GridSecurityProcessorImpl] Authenticate thin client subject; " +
                " login=" + subject.login());

        return res;
    }

    @Override
    public SecurityContext securityContext(UUID subjId) {
        return (SecurityContext) ctx.grid().getOrCreateCache("thin_clients").get(subjId);
    }

    @Override
    public void onSessionExpired(UUID subjId) {
        ctx.grid().getOrCreateCache("thin_clients").remove(subjId);
    }

    @Override
    public void start() throws IgniteCheckedException {
        U.quiet(false, "[GridSecurityProcessorImpl] Start; localNode=" + ctx.localNodeId()
                + ", login=" + localNodeCredentials.getLogin());

        ctx.addNodeAttribute(IgniteNodeAttributes.ATTR_SECURITY_CREDENTIALS, localNodeCredentials);

        super.start();
    }

    @Override
    public boolean enabled() {
        return true;
    }

    @Override
    public boolean sandboxEnabled() {
        return true;
    }

    @Override
    public boolean isGlobalNodeAuthentication() {
        return false;
    }

    @Override
    public void authorize(String name, SecurityPermission perm, SecurityContext secCtx)
            throws SecurityException {
        if (!((SecurityContextImpl) secCtx).operationAllowed(name, perm))
            throw new SecurityException("Authorization failed [perm=" + perm +
                    ", name=" + name +
                    ", subject=" + secCtx.subject() + ']');
    }

    @Override
    public Collection<SecuritySubject> authenticatedSubjects() {
        return null;
    }

    @Override
    public SecuritySubject authenticatedSubject(UUID uuid) {
        return null;
    }
}