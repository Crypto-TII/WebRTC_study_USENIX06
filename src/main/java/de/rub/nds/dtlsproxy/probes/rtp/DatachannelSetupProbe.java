/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.DataChannelCreationProcessor;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Probe that will check if a peer will respond to an SCTP init */
public abstract class DatachannelSetupProbe extends SingleSideMediaProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private DataChannelCreationProcessor sctpProcessor;

    private final boolean probeServer;

    private final WebRtcProperties propertyResponds;

    public DatachannelSetupProbe(
            WebrtcExecutionContext webrtcExecutionContext, ConnectionEndType probingPeer) {
        super(
                webrtcExecutionContext,
                "SCTP DATACHANNEL SETUP",
                probingPeer == ConnectionEndType.CLIENT);
        this.probeServer = probingPeer == ConnectionEndType.SERVER;
        this.propertyResponds =
                probeServer
                        ? WebRtcProperties.SERVER_RESPONDS_TO_SCTP_INIT
                        : WebRtcProperties.CLIENT_RESPONDS_TO_SCTP_INIT;
    }

    @Override
    protected synchronized void postDtlsCheck(TraceableConnection rtpConnection) {
        getMediaReport()
                .putAdditionalResult(
                        propertyResponds, new DetailedResult<String>(TestResults.NOT_TESTED_YET));

        super.postDtlsCheck(rtpConnection);

        String remoteParty = probeServer ? "Server" : "Client";

        if (getIngoingDtlsChainEnd().wasDataProcessed()) {
            LOGGER.info("{} responded to SCTP INIT", remoteParty);
            getMediaReport().putAdditionalResult(propertyResponds, DetailedResult.TRUE());
        } else {
            LOGGER.info("{} ignored SCTP INIT", remoteParty);
            getMediaReport().putAdditionalResult(propertyResponds, DetailedResult.FALSE());
        }
    }

    @Override
    protected void startProcessors(HookedConnection hookedConnection) {

        sctpProcessor = new DataChannelCreationProcessor();
        sctpProcessor.setNext(getOutgoingDtlsChainStart());

        try {
            sctpProcessor.start();
        } catch (IOException e) {
            throw new RuntimeException("Failed to kick off SCTP processor");
        }

        super.startProcessors(hookedConnection);
    }
}
