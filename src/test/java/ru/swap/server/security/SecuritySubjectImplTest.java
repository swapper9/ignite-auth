package ru.swap.server.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.Permissions;
import java.security.cert.Certificate;
import java.util.UUID;

import org.apache.ignite.plugin.security.SecurityBasicPermissionSet;
import org.apache.ignite.plugin.security.SecuritySubjectType;
import org.junit.jupiter.api.Test;

class SecuritySubjectImplTest {
    @Test
    void testId() {
        assertNull((new SecuritySubjectImpl()).id());
    }

    @Test
    void testType() {
        assertNull((new SecuritySubjectImpl()).type());
    }

    @Test
    void testLogin() {
        assertNull((new SecuritySubjectImpl()).login());
    }

    @Test
    void testAddress() {
        assertNull((new SecuritySubjectImpl()).address());
    }

    @Test
    void testPermissions() {
        assertNull((new SecuritySubjectImpl()).permissions());
    }

    @Test
    void testCertificates() {
        assertNull((new SecuritySubjectImpl()).certificates());
    }

    @Test
    void testSandboxPermissions() {
        assertNull((new SecuritySubjectImpl()).sandboxPermissions());
    }

    @Test
    void testConstructor() {
        SecuritySubjectImpl actualSecuritySubjectImpl = new SecuritySubjectImpl();
        actualSecuritySubjectImpl.certificates(new Certificate[]{null});
        actualSecuritySubjectImpl.id(UUID.randomUUID());
        actualSecuritySubjectImpl.login("Login");
        actualSecuritySubjectImpl.permissions(new SecurityBasicPermissionSet());
        actualSecuritySubjectImpl.sandboxPermissions(new Permissions());
        actualSecuritySubjectImpl.type(SecuritySubjectType.REMOTE_NODE);
        assertEquals("TestSecuritySubject{login=Login}", actualSecuritySubjectImpl.toString());
    }
}

