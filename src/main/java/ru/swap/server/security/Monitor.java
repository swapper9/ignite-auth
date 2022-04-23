package ru.swap.server.security;

import org.apache.ignite.IgniteLogger;
import org.apache.ignite.internal.GridKernalContext;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class Monitor extends Thread {

    private final File file;
    private final IgniteLogger logger;
    private AtomicBoolean stop = new AtomicBoolean(false);
    private volatile boolean isChanged = false;

    public Monitor(File file, GridKernalContext ctx) {
        setDaemon(true);
        this.file = file;
        this.logger = ctx.log(Monitor.class);
    }

    public boolean isStopped() {
        return stop.get();
    }

    public void stopThread() {
        stop.set(true);
    }

    public void doOnChange() {
        isChanged = true;
    }

    public boolean hasChanged() {
        if (isChanged) {
            isChanged = false;
            return true;
        }
        return false;
    }

    @Override
    public void run() {
        try(WatchService watcher = FileSystems.getDefault().newWatchService()) {
            Path path = file.toPath().getParent();
            path.register(watcher, StandardWatchEventKinds.ENTRY_MODIFY);
            while(!isStopped()) {
                WatchKey key;
                try {
                    key = watcher.poll(25, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    return;
                }
                if (key == null) {
                    Thread.yield();
                    continue;
                }

                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();

                    @SuppressWarnings("unchecked")
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();

                    if (kind == StandardWatchEventKinds.OVERFLOW) {
                        Thread.yield();
                        continue;
                    } else if (kind == StandardWatchEventKinds.ENTRY_MODIFY && filename.toString().equals(file.getName())) {
                        doOnChange();
                    }
                    boolean valid = key.reset();
                    if (!valid) {
                        break;
                    }
                }
                Thread.yield();
            }
        } catch (Exception e) {
            logger.error("Error checking configuration changes: ", e);
        }
    }
}
