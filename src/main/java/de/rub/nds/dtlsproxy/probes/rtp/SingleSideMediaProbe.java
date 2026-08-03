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
import de.rub.nds.dtlsproxy.enums.MitmProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.processing.DumpingProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.PlaintextLogProcessor;
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
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import de.rub.nds.dtlsproxy.util.MediaDumper;
import de.rub.nds.scanner.core.probe.result.TestResults;

/** Post DTLS probe that will try to decrypt all DTLS, SRTP and SRTCP traffic to send own traffic */
public abstract class SingleSideMediaProbe extends RtpProbe {

    private final long testDuration;

    private MediaDumper serverToClientPlaintextDumper = null;
    private MediaDumper clientToServerPlaintextDumper = null;

    private final ThreadGroup receivingThreads = new ThreadGroup("Receivers");

    private PlaintextLogProcessor outgoingSrtpLoggingProcessor;
    private DumpingProcessor outgoingSrtpDumpingProcessor;
    private SrtpEncryptingProcessor srtpEncryptingProcessor;

    private PlaintextLogProcessor outgoingSrtcpLoggingProcessor;
    private DumpingProcessor outgoingSrtcpDumpingProcessor;
    private SrtcpEncryptingProcessor srtcpEncryptingProcessor;

    private PlaintextLogProcessor outgoingDtlsLoggingProcessor;
    private DumpingProcessor outgoingDtlsDumpingProcessor;
    private DtlsEncryptingProcessor dtlsEncryptingProcessor;

    private PlaintextLogProcessor ingoingSrtpLoggingProcessor;
    private DumpingProcessor ingoingSrtpDumpingProcessor;
    private SrtpDecryptingProcessor srtpDecryptingProcessor;

    private PlaintextLogProcessor ingoingSrtcpLoggingProcessor;
    private DumpingProcessor ingoingSrtcpDumpingProcessor;
    private SrtcpDecryptingProcessor srtcpDecryptingProcessor;

    private PlaintextLogProcessor ingoingDtlsLoggingProcessor;
    private DumpingProcessor ingoingDtlsDumpingProcessor;
    private DtlsDecryptingProcessor dtlsDecryptingProcessor;

    private boolean actingAsServer;

    protected SingleSideMediaProbe(
            WebrtcExecutionContext webrtcExecutionContext, String label, boolean actingAsServer) {
        super(webrtcExecutionContext, label, !actingAsServer, actingAsServer);
        setEnableSrtp(true);
        this.testDuration = getProxyConfiguration().getMediaProcessDuration();
        this.actingAsServer = actingAsServer;
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

        initResults();
        createProcessors();
        chainProcessors(hookedConnection);
        startProcessors(hookedConnection);
        joinThreads();
        setResults();

        LOGGER.info("Post DTLS re-encrypt check concluded.");
    }

    private void createProcessors() {
        outgoingSrtpLoggingProcessor = new PlaintextLogProcessor(actingAsServer, "RTP");
        outgoingSrtcpLoggingProcessor = new PlaintextLogProcessor(actingAsServer, "RTCP");
        outgoingDtlsLoggingProcessor = new PlaintextLogProcessor(actingAsServer, "DTLS");
        ingoingSrtpLoggingProcessor = new PlaintextLogProcessor(!actingAsServer, "RTP");
        ingoingSrtcpLoggingProcessor = new PlaintextLogProcessor(!actingAsServer, "RTCP");
        ingoingDtlsLoggingProcessor = new PlaintextLogProcessor(!actingAsServer, "DTLS");
        outgoingSrtpDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? serverToClientPlaintextDumper
                                : clientToServerPlaintextDumper);
        outgoingSrtcpDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? serverToClientPlaintextDumper
                                : clientToServerPlaintextDumper);
        outgoingDtlsDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? serverToClientPlaintextDumper
                                : clientToServerPlaintextDumper);
        ingoingSrtpDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? clientToServerPlaintextDumper
                                : serverToClientPlaintextDumper);
        ingoingSrtcpDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? clientToServerPlaintextDumper
                                : serverToClientPlaintextDumper);
        ingoingDtlsDumpingProcessor =
                new DumpingProcessor(
                        actingAsServer
                                ? clientToServerPlaintextDumper
                                : serverToClientPlaintextDumper);
        srtpEncryptingProcessor =
                new SrtpEncryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerRtpCrypto()
                                : getAttackerToServerRtpCrypto());
        srtpDecryptingProcessor =
                new SrtpDecryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerRtpCrypto()
                                : getAttackerToServerRtpCrypto());
        srtcpEncryptingProcessor =
                new SrtcpEncryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerRtpCrypto()
                                : getAttackerToServerRtpCrypto());
        srtcpDecryptingProcessor =
                new SrtcpDecryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerRtpCrypto()
                                : getAttackerToServerRtpCrypto());
        dtlsEncryptingProcessor =
                new DtlsEncryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerTlsContext()
                                : getAttackerToServerTlsContext());
        dtlsDecryptingProcessor =
                new DtlsDecryptingProcessor(
                        actingAsServer
                                ? getClientToAttackerTlsContext()
                                : getAttackerToServerTlsContext());
    }

    private void chainProcessors(HookedConnection hookedConnection) {
        ByteArrayWriteout writeToClient =
                data -> hookedConnection.getAttackerToClientTransport().sendData(data);
        ByteArrayWriteout writeToServer =
                data -> hookedConnection.getAttackerToServerTransport().sendData(data);
        ByteArrayWriteout writeToPeer = actingAsServer ? writeToClient : writeToServer;
        srtpEncryptingProcessor.setNext(writeToPeer);
        srtcpEncryptingProcessor.setNext(writeToPeer);
        dtlsEncryptingProcessor.setNext(writeToPeer);
        outgoingSrtpDumpingProcessor.setNext(srtpEncryptingProcessor);
        outgoingSrtcpDumpingProcessor.setNext(srtcpEncryptingProcessor);
        outgoingDtlsDumpingProcessor.setNext(dtlsEncryptingProcessor);
        outgoingSrtpLoggingProcessor.setNext(outgoingSrtpDumpingProcessor);
        outgoingSrtcpLoggingProcessor.setNext(outgoingSrtcpDumpingProcessor);
        outgoingDtlsLoggingProcessor.setNext(outgoingDtlsDumpingProcessor);

        srtpDecryptingProcessor.setNext(ingoingSrtpDumpingProcessor);
        srtcpDecryptingProcessor.setNext(ingoingSrtcpDumpingProcessor);
        dtlsDecryptingProcessor.setNext(ingoingDtlsDumpingProcessor);
        ingoingSrtpDumpingProcessor.setNext(ingoingSrtpLoggingProcessor);
        ingoingSrtcpDumpingProcessor.setNext(ingoingSrtcpLoggingProcessor);
        ingoingDtlsDumpingProcessor.setNext(ingoingDtlsLoggingProcessor);
    }

    protected void startProcessors(HookedConnection hookedConnection) {

        if (actingAsServer) {
            ProcessorInput clientToServerSrtpInput =
                    new ProcessorInput(
                            hookedConnection.getClientToServerRtp(),
                            srtpDecryptingProcessor,
                            testDuration);
            ProcessorInput clientToServerSrtcpInput =
                    new ProcessorInput(
                            hookedConnection.getClientToServerRtcp(),
                            srtcpDecryptingProcessor,
                            testDuration);
            ProcessorInput clientToServerDtlsInput =
                    new ProcessorInput(
                            hookedConnection.getClientToServerDtlsAppData(),
                            dtlsDecryptingProcessor,
                            testDuration);

            clientToServerSrtpInput.startThread(receivingThreads, "SRTP clientToServer");
            clientToServerSrtcpInput.startThread(receivingThreads, "SRTCP clientToServer");
            clientToServerDtlsInput.startThread(receivingThreads, "DTLS clientToServer");
        } else {
            ProcessorInput serverToClientSrtpInput =
                    new ProcessorInput(
                            hookedConnection.getServerToClientRtp(),
                            srtpDecryptingProcessor,
                            testDuration);
            ProcessorInput serverToClientSrtcpInput =
                    new ProcessorInput(
                            hookedConnection.getServerToClientRtcp(),
                            srtcpDecryptingProcessor,
                            testDuration);
            ProcessorInput serverToClientDtlsInput =
                    new ProcessorInput(
                            hookedConnection.getServerToClientDtlsAppData(),
                            dtlsDecryptingProcessor,
                            testDuration);

            serverToClientSrtpInput.startThread(receivingThreads, "SRTP serverToClient");
            serverToClientSrtcpInput.startThread(receivingThreads, "SRTCP serverToClient");
            serverToClientDtlsInput.startThread(receivingThreads, "DTLS serverToClient");
        }
    }

    private void initResults() {
        MediaReport report = getMediaReport();
        report.setResult(
                MediaProtocol.RTP, MitmProperties.DATA_RECEIVED, TestResults.FALSE, actingAsServer);
        report.setResult(
                MediaProtocol.RTP,
                MitmProperties.DECRYPTION_SUCCESS,
                TestResults.COULD_NOT_TEST,
                actingAsServer);
        report.setResult(
                MediaProtocol.RTCP,
                MitmProperties.DATA_RECEIVED,
                TestResults.FALSE,
                actingAsServer);
        report.setResult(
                MediaProtocol.RTCP,
                MitmProperties.DECRYPTION_SUCCESS,
                TestResults.COULD_NOT_TEST,
                actingAsServer);
        report.setResult(
                MediaProtocol.DTLS,
                MitmProperties.DATA_RECEIVED,
                TestResults.FALSE,
                actingAsServer);
        report.setResult(
                MediaProtocol.DTLS,
                MitmProperties.DECRYPTION_SUCCESS,
                TestResults.COULD_NOT_TEST,
                actingAsServer);
    }

    private void setResults() {
        MediaReport report = getMediaReport();
        report.setResult(
                MediaProtocol.RTP,
                MitmProperties.DATA_RECEIVED,
                srtpDecryptingProcessor.wasDataProcessed(),
                actingAsServer);
        if (srtpDecryptingProcessor.wasDataProcessed()) {
            report.setResult(
                    MediaProtocol.RTP,
                    MitmProperties.DECRYPTION_SUCCESS,
                    srtpDecryptingProcessor.wasCryptoSuccessful(),
                    actingAsServer);
        }
        report.setResult(
                MediaProtocol.RTCP,
                MitmProperties.DATA_RECEIVED,
                srtcpDecryptingProcessor.wasDataProcessed(),
                actingAsServer);
        if (srtcpDecryptingProcessor.wasDataProcessed()) {
            report.setResult(
                    MediaProtocol.RTCP,
                    MitmProperties.DECRYPTION_SUCCESS,
                    srtcpDecryptingProcessor.wasCryptoSuccessful(),
                    actingAsServer);
        }
        report.setResult(
                MediaProtocol.DTLS,
                MitmProperties.DATA_RECEIVED,
                dtlsDecryptingProcessor.wasDataProcessed(),
                actingAsServer);
        if (dtlsDecryptingProcessor.wasDataProcessed()) {
            report.setResult(
                    MediaProtocol.DTLS,
                    MitmProperties.DECRYPTION_SUCCESS,
                    dtlsDecryptingProcessor.wasCryptoSuccessful(),
                    actingAsServer);
        }
    }

    /** Will block until all forwarding threads have timed out */
    public void joinThreads() {
        try {
            Thread.sleep(testDuration);
        } catch (InterruptedException ignored) {
        }
        receivingThreads.interrupt();
        clientToServerPlaintextDumper.close();
        serverToClientPlaintextDumper.close();
    }

    /**
     * First processor in the chain for RTP data to leave the probe into the direction configured
     */
    public Processor getOutgoingRtpChainStart() {
        return outgoingSrtpLoggingProcessor;
    }

    /**
     * First processor in the chain for RTCP data to leave the probe into the direction configured
     */
    public Processor getOutgoingRtcpChainStart() {
        return outgoingSrtcpLoggingProcessor;
    }

    /**
     * First processor in the chain for DTLS data to leave the probe into the direction configured
     */
    public Processor getOutgoingDtlsChainStart() {
        return outgoingDtlsLoggingProcessor;
    }

    /** Last processor in the chain of processing RTP data from the input direction configured */
    public Processor getIngoingRtpChainEnd() {
        return ingoingSrtpLoggingProcessor;
    }

    /** Last processor in the chain of processing RTCP data from the input direction configured */
    public Processor getIngoingRtcpChainEnd() {
        return ingoingSrtcpLoggingProcessor;
    }

    /** Last processor in the chain of processing DTLS data from the input direction configured */
    public Processor getIngoingDtlsChainEnd() {
        return ingoingDtlsLoggingProcessor;
    }
}
