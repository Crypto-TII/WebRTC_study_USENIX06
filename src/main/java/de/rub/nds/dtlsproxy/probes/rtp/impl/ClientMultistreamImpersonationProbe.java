/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.SingleSideMediaProbe;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.webex.WebexSctpProcessor;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Will attempt to get media from a Webex Server by impersonating a client through the multistream
 * protocol on the DTLS Datachannel.
 */
public class ClientMultistreamImpersonationProbe extends SingleSideMediaProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private WebexSctpProcessor sctpProcessor;

    private boolean sctpReceived = false;

    public ClientMultistreamImpersonationProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext, "SCTP WEBEX MULTISTREAM", false);
    }

    @Override
    public void runChecks(WebRtcPlatformReport report) {
        super.runChecks(report);

        if (sctpReceived) {
            LOGGER.info("Server responded to SCTP INIT");
        } else {
            LOGGER.info("Server ignored SCTP INIT");
        }
    }

    @Override
    protected void startProcessors(HookedConnection hookedConnection) {

        sctpProcessor = new WebexSctpProcessor(getOutgoingRtpChainStart(), null);
        sctpProcessor.setNext(getOutgoingDtlsChainStart());
        getIngoingDtlsChainEnd().setNext(sctpProcessor);

        try {
            sctpProcessor.start();
        } catch (IOException e) {
            throw new RuntimeException("Failed to kick off SCTP processor");
        }

        super.startProcessors(hookedConnection);
        sctpReceived = getOutgoingDtlsChainStart().wasDataProcessed();
    }
}
