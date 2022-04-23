package ru.swap.server.security;

import com.google.gson.Gson;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.IgniteLogger;
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

import java.io.File;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class GridSecurityProcessorImpl extends GridProcessorAdapter implements GridSecurityProcessor {

    private static final String MARKER = "AUTH";
    private static final Pattern SUBJECT_NAME_PATTERN = Pattern.compile("CN=([^,]*)");
    private final String permissionsPath;
    private final String caPemPath;
    private final Monitor permissionsMonitor;
    private final Monitor certMonitor;
    private final IgniteLogger logger;
    private final SecurityCredentials localNodeCredentials;
    private final Map<String, Subject> permissionMap = new HashMap<>();
    private X509Certificate caCertificate;

    public GridSecurityProcessorImpl(GridKernalContext ctx, SecurityCredentials cred) {
        super(ctx);
        this.logger = ctx.log(GridSecurityProcessorImpl.class);
        localNodeCredentials = cred;

        String configPath = System.getProperty("config.path", "/opt/ignite/config/");
        permissionsPath = configPath + "permissions.json";
        caPemPath = configPath + "ca.pem";

        permissionsMonitor = new Monitor(new File(permissionsPath), ctx);
        permissionsMonitor.start();

        certMonitor = new Monitor(new File(caPemPath), ctx);
        certMonitor.start();

        loadPermissions();
        caCertificate = loadCACertificate();
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
            logger.warning(MARKER, "[GridSecurityProcessorImpl] Login=" + login + " not exist.", null);
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

        logger.info(MARKER, "[GridSecurityProcessorImpl] Authenticate node; " +
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
            logger.info(MARKER, "Client \"" + context.credentials().getLogin() + "\" has no certificate.");
            throw new SecurityException("Authorization failed, no certificates found");
        }

        String principal = ((X509Certificate) certificates[0]).getSubjectX500Principal().getName();
        logger.info(MARKER, "Pribcipal: " + principal + ", login: " + context.credentials().getLogin());

        //Got CN as SubjectName
        Matcher matcher = SUBJECT_NAME_PATTERN.matcher(principal);
        String subjectName = matcher.find() ? matcher.group(1).toUpperCase() : "";
        if (subjectName.isEmpty()) {
            logger.error(MARKER, "Client [context.address=" + context.address() + "] has invalid certificate.", null);
            throw new SecurityException("Authorization failed, certificate not valid [context.address=" + context.address() + "]");
        }

        //Validating certificates
        checkCAConfiguration();
        List<X509Certificate> certList = Arrays.stream(certificates)
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());
        for (X509Certificate cert : certList) {
            try {
                cert.checkValidity();
                cert.verify(caCertificate.getPublicKey());
            } catch (CertificateException e) {
                logger.error(MARKER, "Client \"" + subjectName + "\" has invalid certificate: ", e);
                throw new SecurityException("Authorization failed, certificates not valid [context.address" + context.address() + "]");
            } catch (NoSuchAlgorithmException | SignatureException | NoSuchProviderException | InvalidKeyException e) {
                logger.error(MARKER, "Client \"" + subjectName + "\" certificate has not verified to CA: ", e);
                throw new SecurityException("Authorization failed, certificates not verified [context.address" + context.address() + "]");
            }
        }

        checkPermissionsConfiguration();
        SecuritySubject subject = new SecuritySubjectImpl()
                .id(context.subjectId())
                .login(subjectName)
                .type(SecuritySubjectType.REMOTE_CLIENT)
                .certificates(context.certificates())
                .permissions(getPermissionSet(subjectName));

        SecurityContext res = new SecurityContextImpl(subject);

        ctx.grid().getOrCreateCache("thin_clients").put(subject.id(), res);

        logger.info(MARKER, "[GridSecurityProcessorImpl] Authenticate thin client subject; " +
                "subjectId=" + subject.id() +
                " login=" + subjectName);

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
        logger.info(MARKER, "[GridSecurityProcessorImpl] Start; localNode=" + ctx.localNodeId()
                + ", login=" + localNodeCredentials.getLogin());

        ctx.addNodeAttribute(IgniteNodeAttributes.ATTR_SECURITY_CREDENTIALS, localNodeCredentials);

        super.start();
    }

    private void loadPermissions() {
        permissionMap.clear();
        try (FileReader reader = new FileReader(permissionsPath)) {
            if (!reader.ready()) {
                logger.error(MARKER, "Error loading permissions.", null);
                throw new SecurityException("Permissions loading failed");
            }
            new Gson().fromJson(reader, SubjectList.class)
                    .getSubjects()
                    .forEach(s -> permissionMap.put(s.getLogin(), s));
        } catch (IOException e) {
            logger.error(MARKER, "Error loading permissions: ", e);
            throw new SecurityException("Permissions loading failed");
        }
    }

    private X509Certificate loadCACertificate() {
        try (InputStream is = new FileInputStream(caPemPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (IOException e) {
            throw new SecurityException("CA Certificate loading error: " + e);
        } catch (CertificateException e) {
            throw new SecurityException("CA Certificate error: " + e);
        }
    }

    private void checkPermissionsConfiguration() {
        if (permissionsMonitor.hasChanged()) {
            logger.info(MARKER, "Permissions configuration changed, reloading.");
            loadPermissions();
        }
    }

    private void checkCAConfiguration() {
        if (certMonitor.hasChanged()) {
            logger.info(MARKER, "CA Certificate changed, reloading.");
            caCertificate = loadCACertificate();
        }
    }

    @Override
    public boolean enabled() {
        return true;
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