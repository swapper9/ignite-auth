package ru.swap.server.security;

import com.google.gson.Gson;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.cluster.ClusterNode;
import org.apache.ignite.internal.GridKernalContext;
import org.apache.ignite.internal.IgniteNodeAttributes;
import org.apache.ignite.internal.processors.GridProcessorAdapter;
import org.apache.ignite.internal.processors.security.GridSecurityProcessor;
import org.apache.ignite.internal.processors.security.SecurityContext;
import org.apache.ignite.internal.util.typedef.F;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.plugin.security.SecurityException;
import org.apache.ignite.plugin.security.*;
import ru.swap.server.security.permissions.CachePermission;
import ru.swap.server.security.permissions.ServicePermission;
import ru.swap.server.security.permissions.Subject;
import ru.swap.server.security.permissions.SubjectList;
import ru.swap.server.security.permissions.SystemPermission;

import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class GridSecurityProcessorImpl extends GridProcessorAdapter implements GridSecurityProcessor {

    private final SecurityCredentials localNodeCredentials;
    private final Map<String, Subject> subjectMap = new HashMap<>();

    public GridSecurityProcessorImpl(GridKernalContext ctx, SecurityCredentials cred) {
        super(ctx);
        localNodeCredentials = cred;
        loadSubjects();
    }

    private SecurityPermissionSet getPermissionSet(Object login) {

        if (login.equals("node")) return SecurityPermissionSetBuilder.ALLOW_ALL;

        Optional<Subject> subject = subjectMap.entrySet().stream()
                .filter(s -> s.getKey().equals(login))
                .map(Map.Entry::getValue)
                .findAny();
        if (!subject.isPresent()) {
            U.quiet(false, "[GridSecurityProcessorImpl] Login=" + login + " not exist.");
            return null;
        }

        SecurityPermissionSetBuilder builder = new SecurityPermissionSetBuilder();
        List<ServicePermission> servicePermissions = subject.get().getServicePermissions();
        if (servicePermissions != null && !servicePermissions.isEmpty()) {
            for (ServicePermission sp : servicePermissions) {
                builder.appendServicePermissions(
                        sp.getServiceName(),
                        sp.getSecurityPermissions().toArray(new SecurityPermission[0])
                );
            }
        }

        List<SystemPermission> systemPermissions = subject.get().getSystemPermissions();
        if (systemPermissions != null && !systemPermissions.isEmpty()) {
            for (SystemPermission sp : systemPermissions) {
                builder.appendSystemPermissions(sp.getSecurityPermissions().toArray(new SecurityPermission[0]));
            }
        }

        List<CachePermission> cachePermissions = subject.get().getCachePermissions();
        if (cachePermissions != null && !cachePermissions.isEmpty()) {
            for (CachePermission cp : cachePermissions) {
                builder.appendCachePermissions(
                        cp.getCacheName(),
                        cp.getSecurityPermissions().toArray(new SecurityPermission[0])
                );
            }
        }

        return builder.build();
    }

//    private PermissionCollection getSandboxPermissions(Object login) {
//        PermissionCollection res = new Permissions();
//        if (login.equals("sandboxSubject"))
//            res.add(new PropertyPermission("java.version", "read"));
//        else
//            res.add(new AllPermission());
//        return res;
//    }

    /**
     * Checking the credentials of the joining node
     *
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
                .permissions(getPermissionSet(credentials.getLogin()));
        //.sandboxPermissions(getSandboxPermissions(credentials.getLogin()));

        U.quiet(false, "[GridSecurityProcessorImpl] Authenticate node; " +
                "localNode=" + ctx.localNodeId() +
                ", authenticatedNode=" + node.id() +
                ", login=" + credentials.getLogin());

        return new SecurityContextImpl(subject);
    }

    /**
     * Checking the credentials of the thin client
     *
     * @param context
     * @return
     */
    @Override
    public SecurityContext authenticate(AuthenticationContext context) {

        // This is the place to check the credentials of the thin client.

        //Client SSL certificates to check
        //TODO строку login имеет смысл передавать внутри сертификата,
        // а не брать из контекста аутентификации тонкого клиента
        Certificate[] certificates = context.certificates();

        String login = (String) context.credentials().getLogin();


        ctx.grid().getOrCreateCache("subjects").putAll(subjectMap);

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(context.subjectId())
                .login(context.credentials().getLogin())
                .type(SecuritySubjectType.REMOTE_CLIENT)
                .permissions(getPermissionSet(context.credentials().getLogin()));

        SecurityContext res = new SecurityContextImpl(subject);

        ctx.grid().getOrCreateCache("thin_clients").put(subject.id(), res);

        U.quiet(false, "[GridSecurityProcessorImpl] Authenticate thin client subject; " +
                "subjectId=" + subject.id() +
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

    private void loadSubjects() {
        try {
            new Gson().fromJson(new FileReader("config/permissions.json"), SubjectList.class)
                    .getSubjects()
                    .forEach(s -> subjectMap.put(s.getLogin(), s));
        } catch (IOException e) {
            U.quiet(true, "[GridSecurityProcessorImpl] Exception loading subjects: " + e.getMessage());
        }
    }

    @Override
    public boolean enabled() {
        return true;
    }

    @Override
    public boolean sandboxEnabled() {
        return false;
    }

    @Override
    public boolean isGlobalNodeAuthentication() {
        return false;
    }

    @Override
    public void authorize(String name, SecurityPermission perm, SecurityContext secCtx)
            throws SecurityException {
        if (!((SecurityContextImpl) secCtx).operationAllowed(name, perm))
            throw new SecurityException("Authorization failed [permission=" + perm +
                    ", name=" + name +
                    ", subject=" + secCtx.subject() + ']');
    }

    @Override
    public Collection<SecuritySubject> authenticatedSubjects() {
        return Collections.singletonList(new SecuritySubjectImpl());
    }

    @Override
    public SecuritySubject authenticatedSubject(UUID uuid) {
        return new SecuritySubjectImpl();
    }
}