package ru.swap.server.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;

import org.apache.ignite.plugin.security.SecurityBasicPermissionSet;
import org.apache.ignite.plugin.security.SecurityPermission;
import org.junit.jupiter.api.Test;

class SecurityContextImplTest {
    @Test
    void testConstructor() {
        assertEquals("SecurityContext{subject=TestSecuritySubject{login=null}}",
                (new SecurityContextImpl(new SecuritySubjectImpl())).toString());
    }

    @Test
    void testSubject() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        assertSame(securitySubjectImpl, (new SecurityContextImpl(securitySubjectImpl)).subject());
    }

    @Test
    void testTaskOperationAllowed() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse((new SecurityContextImpl(securitySubjectImpl)).taskOperationAllowed("Task Cls Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testTaskOperationAllowed2() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).taskOperationAllowed("Task Cls Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testCacheOperationAllowed() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse((new SecurityContextImpl(securitySubjectImpl)).cacheOperationAllowed("Cache Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testCacheOperationAllowed2() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).cacheOperationAllowed("Cache Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testServiceOperationAllowed() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse((new SecurityContextImpl(securitySubjectImpl)).serviceOperationAllowed("Srvc Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testServiceOperationAllowed2() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).serviceOperationAllowed("Srvc Name",
                SecurityPermission.CACHE_READ));
    }

    @Test
    void testSystemOperationAllowed() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse((new SecurityContextImpl(securitySubjectImpl)).systemOperationAllowed(SecurityPermission.CACHE_READ));
    }

    @Test
    void testSystemOperationAllowed2() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).systemOperationAllowed(SecurityPermission.CACHE_READ));
    }

    @Test
    void testSystemOperationAllowed3() {
        ArrayList<SecurityPermission> securityPermissionList = new ArrayList<SecurityPermission>();
        securityPermissionList.add(SecurityPermission.CACHE_READ);

        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setSystemPermissions(securityPermissionList);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).systemOperationAllowed(SecurityPermission.CACHE_READ));
    }

    @Test
    void testSystemOperationAllowed4() {
        ArrayList<SecurityPermission> securityPermissionList = new ArrayList<SecurityPermission>();
        securityPermissionList.add(SecurityPermission.CACHE_PUT);

        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setSystemPermissions(securityPermissionList);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertFalse((new SecurityContextImpl(securitySubjectImpl)).systemOperationAllowed(SecurityPermission.CACHE_READ));
    }

    @Test
    void testSystemOperationAllowed5() {
        ArrayList<SecurityPermission> securityPermissionList = new ArrayList<SecurityPermission>();
        securityPermissionList.add(SecurityPermission.CACHE_PUT);
        securityPermissionList.add(SecurityPermission.CACHE_READ);

        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setSystemPermissions(securityPermissionList);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue((new SecurityContextImpl(securitySubjectImpl)).systemOperationAllowed(SecurityPermission.CACHE_READ));
    }

    @Test
    void testOperationAllowed() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.CACHE_READ));
    }

    @Test
    void testOperationAllowed2() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.TASK_EXECUTE));
    }

    @Test
    void testOperationAllowed3() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.CACHE_READ));
    }

    @Test
    void testOperationAllowed4() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.EVENTS_ENABLE));
    }

    @Test
    void testOperationAllowed5() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.SERVICE_DEPLOY));
    }

    @Test
    void testOperationAllowed6() {
        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(new SecurityBasicPermissionSet());
        assertFalse(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.CACHE_CREATE));
    }

    @Test
    void testOperationAllowed7() {
        SecurityBasicPermissionSet securityBasicPermissionSet = new SecurityBasicPermissionSet();
        securityBasicPermissionSet.setDefaultAllowAll(true);

        SecuritySubjectImpl securitySubjectImpl = new SecuritySubjectImpl();
        securitySubjectImpl.permissions(securityBasicPermissionSet);
        assertTrue(
                (new SecurityContextImpl(securitySubjectImpl)).operationAllowed("Op Name", SecurityPermission.CACHE_CREATE));
    }
}

