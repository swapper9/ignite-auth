package ru.swap.server.security;

import java.io.Serializable;
import java.util.UUID;

import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.cluster.ClusterNode;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.processors.security.GridSecurityProcessor;
import org.apache.ignite.plugin.CachePluginContext;
import org.apache.ignite.plugin.CachePluginProvider;
import org.apache.ignite.plugin.ExtensionRegistry;
import org.apache.ignite.plugin.IgnitePlugin;
import org.apache.ignite.plugin.PluginContext;
import org.apache.ignite.plugin.PluginProvider;
import org.apache.ignite.plugin.PluginValidationException;
import org.apache.ignite.plugin.security.SecurityCredentials;

public class SecurityPluginProvider implements PluginProvider<SecurityPluginConfiguration> {

    private final SecurityCredentials localNodeCredentials;

    public SecurityPluginProvider(SecurityCredentials cred) {
        localNodeCredentials = cred;
    }

    @Override
    public Object createComponent(PluginContext ctx, Class cls) {
        if (cls.isAssignableFrom(GridSecurityProcessor.class))
            return new GridSecurityProcessorImpl(((IgniteEx) ctx.grid()).context(), localNodeCredentials);

        return null;
    }

    @Override
    public String name() {
        return "SecurityPluginProvider";
    }

    @Override
    public String version() {
        return "1.0.0";
    }

    @Override
    public String copyright() {
        return "2021";
    }

    @Override
    public IgnitePlugin plugin() {
        return new IgnitePlugin() {
        };
    }

    @Override
    public void initExtensions(PluginContext ctx, ExtensionRegistry registry) throws IgniteCheckedException {

    }

    @Override
    public CachePluginProvider createCacheProvider(CachePluginContext ctx) {
        return null;
    }

    @Override
    public void start(PluginContext ctx) throws IgniteCheckedException {

    }

    @Override
    public void stop(boolean cancel) throws IgniteCheckedException {

    }

    @Override
    public void onIgniteStart() throws IgniteCheckedException {

    }

    @Override
    public void onIgniteStop(boolean cancel) {

    }

    @Override
    public Serializable provideDiscoveryData(UUID nodeId) {
        return null;
    }

    @Override
    public void receiveDiscoveryData(UUID nodeId, Serializable data) {

    }

    @Override
    public void validateNewNode(ClusterNode node) throws PluginValidationException {

    }
}