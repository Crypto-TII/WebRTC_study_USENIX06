/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.enums.MitmProperties;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import de.rub.nds.scanner.core.probe.result.TestResults;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LoggingReencryptProcessor<T, I> extends ReencryptProcessor<T, I> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final MediaReport report;
    private final MediaProtocol protocol;
    private final ByteArrayWriteout plainTextSink;
    private final boolean serverToClient;

    public LoggingReencryptProcessor(
            EncryptionProcessor<T, I> encryptionProcessor,
            DecryptionProcessor<T, I> decryptionProcessor,
            Processor intermediateProcessor,
            ByteArrayWriteout writeToReceiver,
            MediaReport report,
            MediaProtocol protocol,
            ByteArrayWriteout plainTextSink,
            boolean serverToClient) {
        super(encryptionProcessor, decryptionProcessor, intermediateProcessor, writeToReceiver);
        this.report = report;
        this.protocol = protocol;
        this.plainTextSink = plainTextSink;
        this.serverToClient = serverToClient;

        setIntermediateProcessors(
                prependLoggerProcessor(prependDumperProcessor(intermediateProcessor)),
                intermediateProcessor);
        report.setResult(
                protocol, MitmProperties.DATA_RECEIVED, TestResults.FALSE, !serverToClient);
        report.setResult(
                protocol,
                MitmProperties.ENCRYPTION_SUCCESS,
                TestResults.COULD_NOT_TEST,
                !serverToClient);
        report.setResult(
                protocol,
                MitmProperties.DECRYPTION_SUCCESS,
                TestResults.COULD_NOT_TEST,
                !serverToClient);
    }

    @Override
    protected void process(byte[] data) {
        super.process(data);
        updateReport();
    }

    private Processor prependLoggerProcessor(Processor intermediateProcessor) {

        PlaintextLogProcessor logger = new PlaintextLogProcessor(serverToClient, protocol.name());
        logger.setNext(intermediateProcessor);

        return logger;
    }

    private Processor prependDumperProcessor(Processor intermediateProcessor) {

        DumpingProcessor processor = new DumpingProcessor(plainTextSink);
        processor.setNext(intermediateProcessor);

        return processor;
    }

    private void updateReport() {
        report.setResult(
                protocol, MitmProperties.DATA_RECEIVED, wasDataProcessed(), !serverToClient);
        report.setResult(
                protocol, MitmProperties.ENCRYPTION_SUCCESS, encryptionSuccess(), !serverToClient);
        report.setResult(
                protocol, MitmProperties.DECRYPTION_SUCCESS, decryptionSuccess(), !serverToClient);
    }

    public MediaProtocol getProtocol() {
        return protocol;
    }

    public MediaReport getReport() {
        return report;
    }
}
