package ru.swap.server.security;

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
import org.apache.ignite.plugin.security.SecurityPermissionSetBuilder;
import org.apache.ignite.plugin.security.SecuritySubject;
import org.apache.ignite.plugin.security.SecuritySubjectType;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.UUID;

public class GridSecurityProcessorImpl extends GridProcessorAdapter implements GridSecurityProcessor {

    private final SecurityCredentials localNodeCredentials;

    public GridSecurityProcessorImpl(GridKernalContext ctx, SecurityCredentials cred) {
        super(ctx);
        localNodeCredentials = cred;
    }

    public void start() throws IgniteCheckedException {
        U.quiet(false, "[GridSecurityProcessorImpl] Start; localNode=" + ctx.localNodeId()
                + ", login=" + localNodeCredentials.getLogin());
        ctx.addNodeAttribute(IgniteNodeAttributes.ATTR_SECURITY_CREDENTIALS, localNodeCredentials);
        super.start();
    }

    public SecurityContext authenticateNode(ClusterNode node, SecurityCredentials credentials) {
        // This is the place to check the credentials of the joining node.

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(node.id())
                .login(credentials.getLogin())
                .address(new InetSocketAddress(F.first(node.addresses()), 0))
                .type(SecuritySubjectType.REMOTE_NODE)
                .permissions(
                        SecurityPermissionSetBuilder
                                .create()
                                .appendSystemPermissions(SecurityPermission.JOIN_AS_SERVER)
                                .build()
                );
        U.quiet(false, "[GridSecurityProcessorImpl] Authenticate node; " +
                "localNode=" + ctx.localNodeId() +
                ", authenticatedNode=" + node.id() +
                ", login=" + credentials.getLogin());

        return new SecurityContextImpl(subject);
    }

    public boolean enabled() {
        return true;
    }

    public boolean isGlobalNodeAuthentication() {
        return false;
    }

    @Override
    public SecurityContext authenticate(AuthenticationContext ctx) throws IgniteCheckedException {
        return null;
    }

    @Override
    public Collection<SecuritySubject> authenticatedSubjects() throws IgniteCheckedException {
        return null;
    }

    @Override
    public SecuritySubject authenticatedSubject(UUID subjId) throws IgniteCheckedException {
        return null;
    }

    @Override
    public void authorize(String name, SecurityPermission perm, SecurityContext securityCtx) throws SecurityException {

    }

    @Override
    public void onSessionExpired(UUID subjId) {

    }

    // other no-op methods of GridSecurityProcessor
}