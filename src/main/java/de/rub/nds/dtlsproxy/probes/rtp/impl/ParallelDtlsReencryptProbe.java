/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.Probe;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.util.List;

/**
 * Probe that assumes the client starts and maintains multiple separate DTLS connections and also
 * does not select a SRTP cipher suite, f.e. Zoom
 *
 * <p>This needs to be setup manually, but is here in case we want to specifically post-dtls profile
 * a service that uses parallel DTLS sessions
 */
public class ParallelDtlsReencryptProbe extends Probe {

    private final FullReencryptProbe[] connectionReenryptions;

    private final int connections;
    private final int processDuration;

    public ParallelDtlsReencryptProbe(
            WebrtcExecutionContext webrtcExecutionContext, int connections, boolean enableSrtp) {
        super(webrtcExecutionContext);
        this.connections = connections;
        this.connectionReenryptions = new FullReencryptProbe[connections];
        this.processDuration = getProxyConfiguration().getMediaProcessDuration();

        for (int i = 0; i < connections; i++) {
            this.connectionReenryptions[i] = new FullReencryptProbe(webrtcExecutionContext);
            this.connectionReenryptions[i].setEnableSrtp(enableSrtp);
            // beware, no booter is called at all! have the page at the ready yourself!
            this.connectionReenryptions[i].setSilentConnectionFetch(true);
        }
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {

        // both probes write into the same report -> beware of race conditions

        Thread[] connectionThreads = new Thread[connections];

        for (int i = 0; i < connections; i++) {
            int finalI = i;
            connectionThreads[i] =
                    new Thread(
                            () -> this.connectionReenryptions[finalI].runChecks(report),
                            "DTLS" + i);
        }

        // kick off individual probe threads
        for (int i = 0; i < connections; i++) {
            connectionThreads[i].start();
        }

        // await individual termination
        try {
            for (int i = 0; i < connections; i++) {
                connectionThreads[i].join(processDuration);
            }
        } catch (InterruptedException ignored) {
        }
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of();
    }
}
