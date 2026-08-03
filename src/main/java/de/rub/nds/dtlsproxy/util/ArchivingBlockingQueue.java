/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

public class ArchivingBlockingQueue<T> extends LinkedBlockingQueue<T> {

    private final List<T> history;

    public ArchivingBlockingQueue() {
        this.history = new ArrayList<>();
    }

    /** Returns the entire queue history as a copy */
    public List<T> getHistory() {
        synchronized (history) {
            return new ArrayList<>(history);
        }
    }

    @Override
    public boolean add(T element) {
        synchronized (history) {
            history.add(element);
        }
        return super.add(element);
    }

    @Override
    public void put(T element) throws InterruptedException {
        synchronized (history) {
            history.add(element);
        }
        super.put(element);
    }

    @Override
    public boolean addAll(Collection<? extends T> c) {
        synchronized (history) {
            history.addAll(c);
        }
        return super.addAll(c);
    }
}
