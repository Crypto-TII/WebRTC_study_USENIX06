/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption.implementation;

import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.RtpProbe;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.util.MediaDumper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Post DTLS probe that will try to decrypt all DTLS, SRTP and SRTCP traffic and send it reencrypted
 * to the next interface if specified, based on the keys derived from the DTLS handshake
 */
public abstract class LegacyReencryptProbe extends RtpProbe {

    protected static final Logger LOGGER = LogManager.getLogger(LegacyReencryptProbe.class);

    /**
     * Whether the postDtlsCheck should block until all reencryption threads terminate / time out
     */
    private boolean asynchronous = false;

    private final long testDuration;

    private final boolean enableClientToAttackerSrtpEncryption;
    private final boolean enableClientToAttackerSrtcpEncryption;
    private final boolean enableClientToAttackerDtlsEncryption;
    private final boolean enableAttackerToServerSrtpEncryption;
    private final boolean enableAttackerToServerSrtcpEncryption;
    private final boolean enableAttackerToServerDtlsEncryption;

    private SrtpReencryptionHandler srtpReencryptionHandler;
    private SrtcpReencryptionHandler srtcpReencryptionHandler;
    private DtlsReencryptionHandler dtlsReencryptionHandler;

    private MediaDumper serverToClientPlaintextDumper = null;
    private MediaDumper clientToServerPlaintextDumper = null;

    public LegacyReencryptProbe(WebrtcExecutionContext webrtcExecutionContext, String label) {
        super(webrtcExecutionContext, label, true, true);
        setEnableSrtp(true);
        this.testDuration = getProxyConfiguration().getMediaProcessDuration();
        this.enableClientToAttackerSrtpEncryption = true;
        this.enableClientToAttackerSrtcpEncryption = true;
        this.enableClientToAttackerDtlsEncryption = true;
        this.enableAttackerToServerSrtpEncryption = true;
        this.enableAttackerToServerSrtcpEncryption = true;
        this.enableAttackerToServerDtlsEncryption = true;
        try {
            serverToClientPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), true, "legacy");
            clientToServerPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), false, "legacy");
        } catch (Exception e) {
            LOGGER.warn("Failed to initialize plaintext dumping: ", e);
        }
    }

    public LegacyReencryptProbe(
            WebrtcExecutionContext webrtcExecutionContext,
            String label,
            boolean enableClientToAttackerSrtpEncryption,
            boolean enableClientToAttackerSrtcpEncryption,
            boolean enableClientToAttackerDtlsEncryption,
            boolean enableAttackerToServerSrtpEncryption,
            boolean enableAttackerToServerSrtcpEncryption,
            boolean enableAttackerToServerDtlsEncryption) {
        super(webrtcExecutionContext, label, true, true);
        setEnableSrtp(true);
        this.testDuration = getProxyConfiguration().getMediaProcessDuration();
        this.enableClientToAttackerSrtpEncryption = enableClientToAttackerSrtpEncryption;
        this.enableClientToAttackerSrtcpEncryption = enableClientToAttackerSrtcpEncryption;
        this.enableClientToAttackerDtlsEncryption = enableClientToAttackerDtlsEncryption;
        this.enableAttackerToServerSrtpEncryption = enableAttackerToServerSrtpEncryption;
        this.enableAttackerToServerSrtcpEncryption = enableAttackerToServerSrtcpEncryption;
        this.enableAttackerToServerDtlsEncryption = enableAttackerToServerDtlsEncryption;
        try {
            serverToClientPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), true, "legacy");
            clientToServerPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), false, "legacy");
        } catch (Exception e) {
            LOGGER.warn("Failed to initialize plaintext dumping: ", e);
        }
    }

    @Override
    protected synchronized void postDtlsCheck(TraceableConnection rtpConnection) {

        if (!(rtpConnection.getConnectionInterface() instanceof HookedConnection))
            throw new RuntimeException("Not implemented");

        LOGGER.info("Starting post DTLS re-encrypt check");

        HookedConnection hookedConnection =
                (HookedConnection) rtpConnection.getConnectionInterface();

        // initialize pcap logger with new connection data
        if (serverToClientPlaintextDumper != null) {
            serverToClientPlaintextDumper.setAssociatedConnection(hookedConnection);
        }
        if (clientToServerPlaintextDumper != null) {
            clientToServerPlaintextDumper.setAssociatedConnection(hookedConnection);
        }

        srtpReencryptionHandler =
                new SrtpReencryptionHandler(
                        getClientToAttackerRtpCrypto(),
                        getAttackerToServerRtpCrypto(),
                        hookedConnection,
                        testDuration,
                        getMediaReport(),
                        serverToClientPlaintextDumper,
                        clientToServerPlaintextDumper,
                        enableClientToAttackerSrtpEncryption,
                        enableAttackerToServerSrtpEncryption);
        srtcpReencryptionHandler =
                new SrtcpReencryptionHandler(
                        getClientToAttackerRtpCrypto(),
                        getAttackerToServerRtpCrypto(),
                        hookedConnection,
                        testDuration,
                        getMediaReport(),
                        serverToClientPlaintextDumper,
                        clientToServerPlaintextDumper,
                        enableClientToAttackerSrtcpEncryption,
                        enableAttackerToServerSrtcpEncryption);
        dtlsReencryptionHandler =
                new DtlsReencryptionHandler(
                        getClientToAttackerTlsContext(),
                        getAttackerToServerTlsContext(),
                        hookedConnection,
                        testDuration,
                        getMediaReport(),
                        serverToClientPlaintextDumper,
                        clientToServerPlaintextDumper,
                        enableClientToAttackerDtlsEncryption,
                        enableAttackerToServerDtlsEncryption);

        srtpReencryptionHandler.startThreads();
        srtcpReencryptionHandler.startThreads();
        dtlsReencryptionHandler.startThreads();

        if (!asynchronous) joinThreads();

        LOGGER.info("Post DTLS re-encrypt check concluded.");
    }

    /** Will block until all forwarding threads have terminated or timed out */
    public void joinThreads() {
        // TODO improve thread handling
        new Thread(dtlsReencryptionHandler::joinThreads).start();
        new Thread(srtcpReencryptionHandler::joinThreads).start();
        srtpReencryptionHandler.joinThreads();
    }

    /** Wether the postDtlsCheck blocks until all reencryption threads terminate / time out */
    public boolean isAsynchronous() {
        return asynchronous;
    }

    /** Wether the postDtlsCheck should block until all reencryption threads terminate / time out */
    public void setAsynchronous(boolean asynchronous) {
        this.asynchronous = asynchronous;
    }
}
