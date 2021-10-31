package ru.swap.server.security;

import java.net.InetSocketAddress;
import java.util.UUID;

import org.apache.ignite.plugin.security.SecurityPermissionSet;
import org.apache.ignite.plugin.security.SecuritySubject;
import org.apache.ignite.plugin.security.SecuritySubjectType;

public class SecuritySubjectImpl implements SecuritySubject {

    private static final long serialVersionUID = 6026611708453669739L;

    private UUID id;
    private SecuritySubjectType type;
    private Object login;
    private InetSocketAddress address;
    private SecurityPermissionSet permissions;

    public UUID id() {
        return id;
    }

    public SecuritySubjectImpl id(UUID id) {
        this.id = id;
        return this;
    }

    public SecuritySubjectType type() {
        return type;
    }

    public SecuritySubjectImpl type(SecuritySubjectType type) {
        this.type = type;
        return this;
    }

    public Object login() {
        return login;
    }

    public SecuritySubjectImpl login(Object login) {
        this.login = login;
        return this;
    }

    public InetSocketAddress address() {
        return address;
    }

    public SecuritySubjectImpl address(InetSocketAddress address) {
        this.address = address;
        return this;
    }

    public SecurityPermissionSet permissions() {
        return permissions;
    }

    public SecuritySubjectImpl permissions(SecurityPermissionSet permissions) {
        this.permissions = permissions;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "TestSecuritySubject{" +
                "login=" + login +
                '}';
    }
}
