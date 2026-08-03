/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.processing.ForwardProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.JsonSsrcSwapProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.LoggingReencryptProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.Processor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.ProcessorInput;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.DtlsDecryptingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.DtlsEncryptingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtcpDecryptingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtcpEncryptingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtpDecryptingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtpEncryptingProcessor;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import de.rub.nds.dtlsproxy.util.MediaDumper;

/**
 * Post DTLS probe that will try to decrypt all DTLS, SRTP and SRTCP traffic and send it reencrypted
 * to the next interface if specified, based on the keys derived from the DTLS handshake
 */
public abstract class ReencryptProbe extends RtpProbe {

    private final long testDuration;

    private final boolean enableClientToAttackerSrtpEncryption;
    private final boolean enableClientToAttackerSrtcpEncryption;
    private final boolean enableClientToAttackerDtlsEncryption;
    private final boolean enableAttackerToServerSrtpEncryption;
    private final boolean enableAttackerToServerSrtcpEncryption;
    private final boolean enableAttackerToServerDtlsEncryption;

    private MediaDumper serverToClientPlaintextDumper = null;
    private MediaDumper clientToServerPlaintextDumper = null;

    private LoggingReencryptProcessor clientToServerSrtpProcessor;
    private LoggingReencryptProcessor serverToClientSrtpProcessor;
    private LoggingReencryptProcessor clientToServerSrtcpProcessor;
    private LoggingReencryptProcessor serverToClientSrtcpProcessor;
    private LoggingReencryptProcessor clientToServerDtlsProcessor;
    private LoggingReencryptProcessor serverToClientDtlsProcessor;

    private ThreadGroup reencryptionThreads = new ThreadGroup("Reencryption");

    protected ReencryptProbe(WebrtcExecutionContext webrtcExecutionContext, String label) {
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
                    new MediaDumper(getProxyConfiguration(), true, getClass().getSimpleName());
            clientToServerPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), false, getClass().getSimpleName());
        } catch (Exception e) {
            LOGGER.warn("Failed to initialize plaintext dumping: ", e);
        }
    }

    protected ReencryptProbe(
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
                    new MediaDumper(getProxyConfiguration(), true, getClass().getSimpleName());
            clientToServerPlaintextDumper =
                    new MediaDumper(getProxyConfiguration(), false, getClass().getSimpleName());
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

        startProcessors(hookedConnection);

        LOGGER.info("Post DTLS re-encrypt check concluded.");
    }

    private void startProcessors(HookedConnection hookedConnection) {

        ByteArrayWriteout writeToClient =
                data -> hookedConnection.getAttackerToClientTransport().sendData(data);
        ByteArrayWriteout writeToServer =
                data -> hookedConnection.getAttackerToServerTransport().sendData(data);
        clientToServerSrtpProcessor =
                new LoggingReencryptProcessor<>(
                        new SrtpEncryptingProcessor(getAttackerToServerRtpCrypto()),
                        new SrtpDecryptingProcessor(getClientToAttackerRtpCrypto()),
                        new ForwardProcessor(),
                        writeToServer,
                        getMediaReport(),
                        MediaProtocol.RTP,
                        clientToServerPlaintextDumper,
                        false);
        serverToClientSrtpProcessor =
                new LoggingReencryptProcessor<>(
                        new SrtpEncryptingProcessor(getClientToAttackerRtpCrypto()),
                        new SrtpDecryptingProcessor(getAttackerToServerRtpCrypto()),
                        new ForwardProcessor(),
                        writeToClient,
                        getMediaReport(),
                        MediaProtocol.RTP,
                        serverToClientPlaintextDumper,
                        true);
        clientToServerSrtcpProcessor =
                new LoggingReencryptProcessor<>(
                        new SrtcpEncryptingProcessor(getAttackerToServerRtpCrypto()),
                        new SrtcpDecryptingProcessor(getClientToAttackerRtpCrypto()),
                        new ForwardProcessor(),
                        writeToServer,
                        getMediaReport(),
                        MediaProtocol.RTCP,
                        clientToServerPlaintextDumper,
                        false);
        serverToClientSrtcpProcessor =
                new LoggingReencryptProcessor<>(
                        new SrtcpEncryptingProcessor(getClientToAttackerRtpCrypto()),
                        new SrtcpDecryptingProcessor(getAttackerToServerRtpCrypto()),
                        new ForwardProcessor(),
                        writeToClient,
                        getMediaReport(),
                        MediaProtocol.RTCP,
                        serverToClientPlaintextDumper,
                        true);
        clientToServerDtlsProcessor =
                new LoggingReencryptProcessor<>(
                        new DtlsEncryptingProcessor(getAttackerToServerTlsContext()),
                        new DtlsDecryptingProcessor(getClientToAttackerTlsContext()),
                        new ForwardProcessor(),
                        writeToServer,
                        getMediaReport(),
                        MediaProtocol.DTLS,
                        clientToServerPlaintextDumper,
                        false);
        serverToClientDtlsProcessor =
                new LoggingReencryptProcessor<>(
                        new DtlsEncryptingProcessor(getClientToAttackerTlsContext()),
                        new DtlsDecryptingProcessor(getAttackerToServerTlsContext()),
                        new ForwardProcessor(),
                        writeToClient,
                        getMediaReport(),
                        MediaProtocol.DTLS,
                        serverToClientPlaintextDumper,
                        true);

        JsonSsrcSwapProcessor filterProcessor = new JsonSsrcSwapProcessor();
        filterProcessor.setNext(clientToServerDtlsProcessor.getFirstIntermediateProcessor());
        clientToServerDtlsProcessor.setIntermediateProcessors(
                filterProcessor, clientToServerDtlsProcessor.getLastIntermediateProcessor());

        clientToServerSrtpProcessor.setEnableDecryption(enableClientToAttackerSrtpEncryption);
        clientToServerSrtpProcessor.setEnableEncryption(enableAttackerToServerSrtpEncryption);
        serverToClientSrtpProcessor.setEnableDecryption(enableAttackerToServerSrtpEncryption);
        serverToClientSrtpProcessor.setEnableEncryption(enableClientToAttackerSrtpEncryption);
        clientToServerSrtcpProcessor.setEnableDecryption(enableClientToAttackerSrtcpEncryption);
        clientToServerSrtcpProcessor.setEnableEncryption(enableAttackerToServerSrtcpEncryption);
        serverToClientSrtcpProcessor.setEnableDecryption(enableAttackerToServerSrtcpEncryption);
        serverToClientSrtcpProcessor.setEnableEncryption(enableClientToAttackerSrtcpEncryption);
        clientToServerDtlsProcessor.setEnableDecryption(enableClientToAttackerDtlsEncryption);
        clientToServerDtlsProcessor.setEnableEncryption(enableAttackerToServerDtlsEncryption);
        serverToClientDtlsProcessor.setEnableDecryption(enableAttackerToServerDtlsEncryption);
        serverToClientDtlsProcessor.setEnableEncryption(enableClientToAttackerDtlsEncryption);

        ProcessorInput clientToServerSrtpInput =
                new ProcessorInput(
                        hookedConnection.getClientToServerRtp(),
                        clientToServerSrtpProcessor,
                        testDuration);
        ProcessorInput serverToClientSrtpInput =
                new ProcessorInput(
                        hookedConnection.getServerToClientRtp(),
                        serverToClientSrtpProcessor,
                        testDuration);
        ProcessorInput clientToServerSrtcpInput =
                new ProcessorInput(
                        hookedConnection.getClientToServerRtcp(),
                        clientToServerSrtcpProcessor,
                        testDuration);
        ProcessorInput serverToClientSrtcpInput =
                new ProcessorInput(
                        hookedConnection.getServerToClientRtcp(),
                        serverToClientSrtcpProcessor,
                        testDuration);
        ProcessorInput clientToServerDtlsInput =
                new ProcessorInput(
                        hookedConnection.getClientToServerDtlsAppData(),
                        clientToServerDtlsProcessor,
                        testDuration);
        ProcessorInput serverToClientDtlsInput =
                new ProcessorInput(
                        hookedConnection.getServerToClientDtlsAppData(),
                        serverToClientDtlsProcessor,
                        testDuration);

        clientToServerSrtpInput.startThread(reencryptionThreads, "SRTP clientToServer");
        serverToClientSrtpInput.startThread(reencryptionThreads, "SRTP serverToClient");
        clientToServerSrtcpInput.startThread(reencryptionThreads, "SRTCP clientToServer");
        serverToClientSrtcpInput.startThread(reencryptionThreads, "SRTCP serverToClient");
        clientToServerDtlsInput.startThread(reencryptionThreads, "DTLS clientToServer");
        serverToClientDtlsInput.startThread(reencryptionThreads, "DTLS serverToClient");

        joinThreads();
    }

    public void setClientToServerFilter(Processor filterProcessor) {
        filterProcessor.setNext(clientToServerDtlsProcessor.getFirstIntermediateProcessor());
        clientToServerDtlsProcessor.setIntermediateProcessors(
                filterProcessor, clientToServerDtlsProcessor.getLastIntermediateProcessor());
    }

    public void setServerToClientFilter(Processor filterProcessor) {
        filterProcessor.setNext(serverToClientDtlsProcessor.getFirstIntermediateProcessor());
        serverToClientDtlsProcessor.setIntermediateProcessors(
                filterProcessor, serverToClientDtlsProcessor.getLastIntermediateProcessor());
    }

    /** Will block until all forwarding threads have timed out */
    public void joinThreads() {
        try {
            Thread.sleep(testDuration);
        } catch (InterruptedException ignored) {
        }
        reencryptionThreads.interrupt();
        clientToServerPlaintextDumper.close();
        serverToClientPlaintextDumper.close();
    }
}
