package ru.swap.server.security;

import org.apache.ignite.plugin.PluginConfiguration;
import org.apache.ignite.plugin.security.SecurityCredentials;

public class SecurityPluginConfiguration implements PluginConfiguration {

    private SecurityCredentials securityCredentials;

    public SecurityPluginConfiguration(SecurityCredentials securityCredentials) {
        this.securityCredentials = securityCredentials;
    }

    public SecurityCredentials getSecurityCredentials() {
        return securityCredentials;
    }
}
