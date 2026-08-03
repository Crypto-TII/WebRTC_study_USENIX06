/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption.implementation;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.enums.MitmProperties;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import de.rub.nds.scanner.core.probe.result.TestResults;
import jakarta.xml.bind.DatatypeConverter;
import java.util.concurrent.BlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract handler for decrypting data packets, printing their clear content and re-encrypting them
 *
 * @param <T> Cryptographic handler f.e. TlsContext
 * @param <I> Intermediate datatype used by cryptographic handler f.e. Record
 */
public abstract class ReencryptionHandler<T, I> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final T clientToAttackerCryptoContext;
    private final T attackerToServerCryptoContext;
    private final HookedConnection connection;
    private final Thread serverToClientThread;
    private final Thread clientToServerThread;
    private final long duration;
    private final MediaReport report;
    private final MediaProtocol protocol;
    private final ByteArrayWriteout serverToClientPlaintextSink;
    private final ByteArrayWriteout clientToServerPlaintextSink;
    private final boolean enableClientToAttackerEncryption;
    private final boolean enableAttackerToServerEncryption;

    /**
     * Creates a new Re-Encryption instance
     *
     * @param clientToAttackerCryptoContext cryptographic context for client to attacker connection
     * @param attackerToServerCryptoContext cryptographic context for the attacker to server
     *     connection
     * @param connection connection object to use input streams from and write final data to
     * @param duration duration of the re-encryption, {@see joinThreads()} will block until the
     *     duration timeout is reached
     * @param report report to write results to
     * @param protocol protocol to use for results and logging
     */
    public ReencryptionHandler(
            T clientToAttackerCryptoContext,
            T attackerToServerCryptoContext,
            HookedConnection connection,
            long duration,
            MediaReport report,
            MediaProtocol protocol,
            ByteArrayWriteout serverToClientPlaintextSink,
            ByteArrayWriteout clientToServerPlaintextSink,
            boolean enableClientToAttackerEncryption,
            boolean enableAttackerToServerEncryption) {
        this.clientToAttackerCryptoContext = clientToAttackerCryptoContext;
        this.attackerToServerCryptoContext = attackerToServerCryptoContext;
        this.connection = connection;
        this.duration = duration;
        this.report = report;
        this.protocol = protocol;
        this.serverToClientPlaintextSink = serverToClientPlaintextSink;
        this.clientToServerPlaintextSink = clientToServerPlaintextSink;
        this.enableClientToAttackerEncryption = enableClientToAttackerEncryption;
        this.enableAttackerToServerEncryption = enableAttackerToServerEncryption;

        this.serverToClientThread = createServerToClientThread();
        this.clientToServerThread = createClientToServerThread();
    }

    /**
     * Creates a thread that handles outbound processing. This method should use createRunnable as
     * the Thread runnable
     *
     * @return outbound processing thread
     */
    protected abstract Thread createServerToClientThread();

    /**
     * Creates a thread that handles inbound processing. This method should use createRunnable as
     * the Thread runnable
     *
     * @return inbound processing thread
     */
    protected abstract Thread createClientToServerThread();

    /**
     * Will create a Runnable to be used by threads for reencryption
     *
     * @param inputQueue Queue to take cipher text data from
     * @param serverToClient Wether this is to be labeled as a reencryption from dtls server to dtls
     *     client
     * @param writeout Implementation to use for writing the result
     * @return
     */
    protected Runnable createRunnable(
            BlockingQueue<byte[]> inputQueue, boolean serverToClient, ByteArrayWriteout writeout) {

        final T decryptingContext =
                serverToClient
                        ? getAttackerToServerCryptoContext()
                        : getClientToAttackerCryptoContext();
        final T encryptingContext =
                serverToClient
                        ? getClientToAttackerCryptoContext()
                        : getAttackerToServerCryptoContext();
        final boolean decryptInput =
                serverToClient
                        ? enableAttackerToServerEncryption
                        : enableClientToAttackerEncryption;
        final boolean encryptOutput =
                serverToClient
                        ? enableClientToAttackerEncryption
                        : enableAttackerToServerEncryption;

        return () -> {
            final long startTime = System.currentTimeMillis();

            final String direction = serverToClient ? "serverToClient" : "clientToServer";

            boolean decryptionSuccess = false;
            boolean encryptionSuccess = false;
            int pktCount = 0;

            LOGGER.trace(
                    "Starting re-encryption thread protocol = {}, direction = {}, decryption enabled = {}, encryption enabled = {}",
                    protocol.name(),
                    direction,
                    decryptInput,
                    encryptOutput);

            // set results in case no packages processed and thread terminated
            report.setResult(
                    protocol,
                    MitmProperties.DECRYPTION_SUCCESS,
                    TestResults.CANNOT_BE_TESTED,
                    !serverToClient);
            report.setResult(
                    protocol,
                    MitmProperties.ENCRYPTION_SUCCESS,
                    TestResults.CANNOT_BE_TESTED,
                    !serverToClient);

            while (System.currentTimeMillis() < startTime + getDuration()) {

                // enter most resent results
                if (pktCount > 0) {
                    if (decryptInput) {
                        report.setResult(
                                protocol,
                                MitmProperties.DECRYPTION_SUCCESS,
                                decryptionSuccess,
                                !serverToClient);
                    } else {
                        report.setResult(
                                protocol,
                                MitmProperties.DECRYPTION_SUCCESS,
                                TestResults.CANNOT_BE_TESTED,
                                !serverToClient);
                    }
                    if (encryptOutput) {
                        report.setResult(
                                protocol,
                                MitmProperties.ENCRYPTION_SUCCESS,
                                decryptionSuccess,
                                !serverToClient);
                    } else {
                        report.setResult(
                                protocol,
                                MitmProperties.ENCRYPTION_SUCCESS,
                                TestResults.CANNOT_BE_TESTED,
                                !serverToClient);
                    }
                }
                report.setResult(
                        protocol, MitmProperties.DATA_RECEIVED, pktCount > 0, !serverToClient);

                try {
                    byte[] rawData;
                    try {
                        rawData = inputQueue.take();
                    } catch (InterruptedException e) {
                        // Thread stopped
                        break;
                    }

                    LOGGER.trace(
                            "processing {} {} of length {}: {}",
                            direction,
                            protocol.name(),
                            rawData.length,
                            DatatypeConverter.printHexBinary(rawData));

                    // Parse packet
                    I intermediate = parseToIntermediate(decryptingContext, rawData);

                    pktCount++;

                    if (decryptInput) {
                        // attempt decryption
                        try {
                            intermediate = decrypt(decryptingContext, intermediate);
                        } catch (Exception e) {
                            LOGGER.debug(
                                    "Failed decrypting {} {}: {}", direction, protocol.name(), e);
                            e.printStackTrace();
                            continue;
                        }
                    }

                    decryptionSuccess = true;

                    final byte[] plainBytes = intermediateToPlainBytes(intermediate);

                    LOGGER.debug(
                            "{} {} plain: {}",
                            direction,
                            protocol.name(),
                            DatatypeConverter.printHexBinary(plainBytes));

                    if (serverToClient && serverToClientPlaintextSink != null) {
                        serverToClientPlaintextSink.input(plainBytes);
                    } else if (!serverToClient && clientToServerPlaintextSink != null) {
                        clientToServerPlaintextSink.input(plainBytes);
                    }

                    if (encryptOutput) {
                        // attempt encryption
                        try {
                            intermediate = encrypt(encryptingContext, intermediate);
                            encryptionSuccess = true;
                        } catch (Exception e) {
                            LOGGER.debug(
                                    "Failed encrypting {} {}: {}", direction, protocol.name(), e);
                            continue;
                        }

                        // write re-enrypted
                        writeout.input(intermediateToCipherBytes(intermediate));
                    } else {
                        // write plain version
                        writeout.input(intermediateToPlainBytes(intermediate));
                    }

                } catch (Exception e) {
                    LOGGER.trace("processing failed", e);
                }
            }

            LOGGER.info(
                    "{}: decryption success = {}, encryption success = {}",
                    direction,
                    decryptionSuccess,
                    encryptionSuccess);
        };
    }

    /**
     * Prepares bytes read from the input stream to be passed to the crypto context for decryption
     *
     * @param cryptoContext crypto context
     * @param rawPacket byte array from the input stream
     * @return intermediate object to apply decryption on
     */
    protected abstract I parseToIntermediate(T cryptoContext, byte[] rawPacket);

    /**
     * Decrypts the given ciphertext intermediate with the given crypto context
     *
     * @param cryptoContext context that applies decryption functionality
     * @param ciphertext ciphertext intermediate object after read and parsed from stream
     * @return decrypted intermediate
     */
    protected abstract I decrypt(T cryptoContext, I ciphertext);

    /**
     * Converts the intermediate object to a byte array to be printed by the logger
     *
     * @param intermediate decrypted intermediate
     * @return plain bytes
     */
    protected abstract byte[] intermediateToPlainBytes(I intermediate);

    /**
     * Encrypts the given plaintext intermediate with the given crypto context
     *
     * @param cryptoContext context that applies encryption functionality
     * @param plaintext plaintext intermediate object after decryption
     * @return encrypted intermediate
     */
    protected abstract I encrypt(T cryptoContext, I plaintext);

    /**
     * Serializes the encrypted intermediate object to a byte array
     *
     * @param intermediate encrypted intermediate value
     */
    protected abstract byte[] intermediateToCipherBytes(I intermediate);

    /** Starts processing */
    public void startThreads() {
        serverToClientThread.start();
        clientToServerThread.start();
    }

    /** Awaits end of processing threads until end of test duration */
    public void joinThreads() {
        try {
            serverToClientThread.join(duration);
        } catch (InterruptedException ignored) {
        }
        serverToClientThread.interrupt();
        clientToServerThread.interrupt();
    }

    public T getClientToAttackerCryptoContext() {
        return clientToAttackerCryptoContext;
    }

    public T getAttackerToServerCryptoContext() {
        return attackerToServerCryptoContext;
    }

    public HookedConnection getConnection() {
        return connection;
    }

    public boolean isEnableClientToAttackerEncryption() {
        return enableClientToAttackerEncryption;
    }

    public boolean isEnableAttackerToServerEncryption() {
        return enableAttackerToServerEncryption;
    }

    public Thread getserverToClientThread() {
        return serverToClientThread;
    }

    public Thread getclientToServerThread() {
        return clientToServerThread;
    }

    public long getDuration() {
        return duration;
    }

    public MediaProtocol getProtocol() {
        return protocol;
    }
}
