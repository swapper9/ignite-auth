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
import ru.swap.server.security.permissions.TaskPermission;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class GridSecurityProcessorImpl extends GridProcessorAdapter implements GridSecurityProcessor {

    private final SecurityCredentials localNodeCredentials;
    private final Map<String, Subject> permissionMap = new HashMap<>();
    private X509Certificate caCertificate = null;

    public GridSecurityProcessorImpl(GridKernalContext ctx, SecurityCredentials cred) {
        super(ctx);
        localNodeCredentials = cred;
        loadPermissions();
        loadCACertificate();
    }

    private SecurityPermissionSet getNodePermissionSet() {
        return SecurityPermissionSetBuilder.ALLOW_ALL;
    }

    private SecurityPermissionSet getPermissionSet(Object login) {

        Optional<Subject> subject = permissionMap.entrySet().stream()
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
            for (ServicePermission p : servicePermissions) {
                builder.appendServicePermissions(
                        p.getServiceName(),
                        p.getSecurityPermissions().toArray(new SecurityPermission[0])
                );
            }
        }

        List<SystemPermission> systemPermissions = subject.get().getSystemPermissions();
        if (systemPermissions != null && !systemPermissions.isEmpty()) {
            for (SystemPermission p : systemPermissions) {
                builder.appendSystemPermissions(p.getSecurityPermissions().toArray(new SecurityPermission[0]));
            }
        }

        List<CachePermission> cachePermissions = subject.get().getCachePermissions();
        if (cachePermissions != null && !cachePermissions.isEmpty()) {
            for (CachePermission p : cachePermissions) {
                builder.appendCachePermissions(
                        p.getCacheName(),
                        p.getSecurityPermissions().toArray(new SecurityPermission[0])
                );
            }
        }

        List<TaskPermission> taskPermissions = subject.get().getTaskPermissions();
        if (taskPermissions != null && !taskPermissions.isEmpty()) {
            for (TaskPermission p : taskPermissions) {
                builder.appendTaskPermissions(
                        p.getCacheName(),
                        p.getSecurityPermissions().toArray(new SecurityPermission[0])
                );
            }
        }

        return builder.build();
    }

    /**
     * Checking the credentials of the joining node
     *
     * @param node
     * @param credentials
     * @return
     */
    @Override
    public SecurityContext authenticateNode(ClusterNode node, SecurityCredentials credentials) {

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(node.id())
                .login(credentials.getLogin())
                .address(new InetSocketAddress(F.first(node.addresses()), 0))
                .type(SecuritySubjectType.REMOTE_NODE)
                .permissions(getNodePermissionSet());

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
        //Checking client SSL certificates
        Certificate[] certificates = context.certificates();
        if (certificates == null || certificates.length == 0) {
            U.quiet(true, "Client \"" + context.credentials().getLogin() + "\" has no certificate.");
            throw new SecurityException("Authorization failed, no certificates found");
        }
        List<X509Certificate> certList = Arrays.stream(certificates)
                .map(c -> (X509Certificate) c)
                .collect(Collectors.toList());
        for (X509Certificate cert : certList) {
            try {
                cert.checkValidity();
                cert.verify(caCertificate.getPublicKey());
            } catch (CertificateException | NoSuchAlgorithmException | SignatureException | NoSuchProviderException | InvalidKeyException e) {
                U.quiet(true, "Client \"" + context.credentials().getLogin() + "\" has invalid certificate: " + e);
                throw new SecurityException("Authorization failed, certificates not valid", e);
            }
        }

        SecuritySubject subject = new SecuritySubjectImpl()
                .id(context.subjectId())
                .login(context.credentials().getLogin())
                .type(SecuritySubjectType.REMOTE_CLIENT)
                .certificates(context.certificates())
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

    private void loadPermissions() {
        try {
            new Gson().fromJson(new FileReader("config/permissions.json"), SubjectList.class)
                    .getSubjects()
                    .forEach(s -> permissionMap.put(s.getLogin(), s));
        } catch (IOException e) {
            U.quiet(true, "[GridSecurityProcessorImpl] Error loading permissions: " + e.getMessage());
        }
    }

    private void loadCACertificate() {
        try (InputStream is = new FileInputStream("config/ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCertificate = (X509Certificate) cf.generateCertificate(is);
        } catch (IOException e) {
            U.quiet(true, "CA Certificate loading I/O error: " + e);
        } catch (CertificateException e) {
            U.quiet(true, "CA Certificate error: " + e);
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
    public void authorize(String name, SecurityPermission perm, SecurityContext secCtx) throws SecurityException {
        if (secCtx.subject().permissions() == null || !((SecurityContextImpl) secCtx).operationAllowed(name, perm))
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