/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.exceptions.MissingProofException;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSrtpProtectionProfileProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSrtpProtectionProfileProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        LOGGER.info("Testing which srtp protection profiles are supported by the server");
        AtomicInteger index = new AtomicInteger(0);
        List<SrtpProtectionProfile> offeredSrtpProtectionProfiles =
                new ArrayList<>(Arrays.asList(SrtpProtectionProfile.values()));
        List<SrtpProtectionProfile> supportedProfiles = new ArrayList<>();
        SrtpProtectionProfile lastSrtpProtectionProfile = null;
        try {
            do {
                @SuppressWarnings("unchecked")
                DetailedResult<String> srtpProtectionProfileTestResult =
                        (DetailedResult<String>)
                                executeWithRetries(
                                        () ->
                                                extractSrtpProtectionProfiles(
                                                        offeredSrtpProtectionProfiles,
                                                        index.get(),
                                                        report));
                LOGGER.debug("Server chose: " + srtpProtectionProfileTestResult);

                if (srtpProtectionProfileTestResult.getSummarizedResult()
                        != TestResults.PARTIALLY) {
                    LOGGER.debug("Server did not choose a cipher suite");
                    report.putResult(
                            WebRtcProperties.SERVER_SRTP_SCAN_TERMINATION_SYMBOL_SEEN,
                            srtpProtectionProfileTestResult);
                    break;
                } else {
                    SrtpProtectionProfile chosenProtectionProfile =
                            SrtpProtectionProfile.valueOf(
                                    srtpProtectionProfileTestResult.getDetails());
                    if (lastSrtpProtectionProfile == chosenProtectionProfile) {
                        LOGGER.warn(
                                "Server selecting not offered protection profile: {}",
                                lastSrtpProtectionProfile);
                        report.putResult(
                                WebRtcProperties.SERVER_SRTP_SCAN_TERMINATION_SYMBOL_SEEN,
                                new DetailedResult<>(
                                        TestResults.MAKES_NO_SENSE,
                                        "Server selected profile we did not offer"));
                        break;
                    } else {
                        lastSrtpProtectionProfile = chosenProtectionProfile;
                        supportedProfiles.add(chosenProtectionProfile);
                        offeredSrtpProtectionProfiles.remove(chosenProtectionProfile);
                    }
                }
                index.incrementAndGet();
            } while (true);

            if (supportedProfiles.isEmpty()) {
                LOGGER.warn("Could not extract any supported SRTP profiles");
            }

            report.setServerSupportedProtectionProfiles(supportedProfiles);

            // probe for MKI recognition
            // different applications may accept MKIs of specific length
            LOGGER.info("Testing if the Server accepts custom MKI");
            report.putResult(
                    WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_SINGLE_BYTE,
                    testServerAcceptsCustomMki(supportedProfiles, 1, report));
            report.putResult(
                    WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_TWO_BYTES,
                    testServerAcceptsCustomMki(supportedProfiles, 2, report));
            report.putResult(
                    WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_THREE_BYTES,
                    testServerAcceptsCustomMki(supportedProfiles, 3, report));
            report.putResult(
                    WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_FOUR_BYTES,
                    testServerAcceptsCustomMki(supportedProfiles, 4, report));

            report.putResult(
                    WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_SRTP_PROTECTION_PROFILE,
                    getEnforcesSrtpProtectionProfileOrder(report));
        } catch (Exception e) {
            LOGGER.warn("Could not extract profiles", e);
        }
    }

    private TestResult getEnforcesSrtpProtectionProfileOrder(WebRtcPlatformReport report) {
        List<SrtpProtectionProfile> offeredProfiles = new ArrayList<>();
        for (SrtpProtectionProfile profiles : SrtpProtectionProfile.values()) {
            offeredProfiles.add(profiles);
        }

        @SuppressWarnings("unchecked")
        DetailedResult<String> firstResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractSrtpProtectionProfiles(offeredProfiles, 9999, report));
        LOGGER.debug("Server chose: " + firstResult);
        Collections.reverse(offeredProfiles);
        @SuppressWarnings("unchecked")
        DetailedResult<String> secondResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractSrtpProtectionProfiles(offeredProfiles, 9998, report));

        if (firstResult.getSummarizedResult() != TestResults.PARTIALLY
                || secondResult.getSummarizedResult() != TestResults.PARTIALLY) {
            LOGGER.debug("Could not perform tests, TestResults: {} {}", firstResult, secondResult);
            return new DetailedResult<Serializable>(
                    TestResults.ERROR_DURING_TEST,
                    "" + firstResult.toString() + " " + secondResult.toString());
        }

        SrtpProtectionProfile firstProfile =
                SrtpProtectionProfile.valueOf(firstResult.getDetails());
        SrtpProtectionProfile secondProfile =
                SrtpProtectionProfile.valueOf(secondResult.getDetails());

        if (firstProfile == secondProfile) {
            LOGGER.debug("Server enforces order: {}", firstProfile);
            return new DetailedResult<>(
                    TestResults.TRUE,
                    "Server selected same profile even in reverse order: " + firstProfile);
        } else {
            LOGGER.debug("Server does not enforce order: {} vs {}", firstProfile, secondProfile);
            return new DetailedResult<>(
                    TestResults.FALSE,
                    "Server selected distinct profile when changing order: "
                            + firstProfile
                            + " vs "
                            + secondProfile);
        }
    }

    /**
     * @param offeredSrtpProtectionProfiles
     * @return
     */
    public DetailedResult<String> extractSrtpProtectionProfiles(
            List<SrtpProtectionProfile> offeredSrtpProtectionProfiles,
            int index,
            WebRtcPlatformReport report) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        config.setAddSRTPExtension(true);
        config.setClientSupportedSrtpProtectionProfiles(offeredSrtpProtectionProfiles);
        WorkflowTrace trace = createSrtpExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_SUPPORTED_SRTP_PROTECTION_PROFILES_" + index);
        SrtpProtectionProfile srtpProtectionProfile =
                connection
                        .getState()
                        .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getSelectedSrtpProtectionProfile();
        if (srtpProtectionProfile != null) {
            return new DetailedResult<String>(
                    TestResults.PARTIALLY,
                    srtpProtectionProfile
                            .name()); // We use partially here to indicate that the test is
            // ongoing...
        } else {
            if (trace.getLastReceivingAction() == null) {
                return new DetailedResult<>(TestResults.FALSE, "No response from server");
            }
            for (ProtocolMessage message : trace.getLastReceivingAction().getReceivedMessages()) {
                if (message instanceof AlertMessage) {
                    LOGGER.debug("Received an Alert message. Found proof.");
                    return new DetailedResult<>(
                            TestResults.TRUE, "Received alert message: " + message.toString());
                }
            }
            if (executionAttemptsExceeded()) {
                return new DetailedResult<>(TestResults.FALSE, "Received no alert. No proof.");
            } else {
                throw new MissingProofException();
            }
        }
    }

    private TestResults extractServerAcceptsMki(WebRtcPlatformReport report, WorkflowTrace trace) {
        ServerHelloMessage serverHello = trace.getLastReceivedMessage(ServerHelloMessage.class);
        if (serverHello != null) {

            SrtpExtensionMessage srtpExtensionMessage =
                    serverHello.getExtension(SrtpExtensionMessage.class);
            if (srtpExtensionMessage != null) {
                if (srtpExtensionMessage.getSrtpMki().getValue().length != 0) {
                    return TestResults.TRUE;
                } else {
                    return TestResults.FALSE;
                }
            } else {
                return TestResults.FALSE;
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResults testServerAcceptsCustomMki(
            List<SrtpProtectionProfile> offeredSrtpProtectionProfiles,
            int mkiLength,
            WebRtcPlatformReport report) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        config.setAddSRTPExtension(true);
        config.setClientSupportedSrtpProtectionProfiles(offeredSrtpProtectionProfiles);
        byte[] mki = new byte[mkiLength];
        Arrays.fill(mki, (byte) 0x01);
        config.setSecureRealTimeTransportProtocolMasterKeyIdentifier(mki);
        WorkflowTrace trace = createSrtpExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_ACCEPTS_MKI_OF_LEN_" + mkiLength);
        return extractServerAcceptsMki(report, trace);
    }

    /**
     * Creates a trace that probes a server for supported srtp protection profiles
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     *                           Send     |---ClientHello--->|
     *                       Receive Till |<------SHD--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createSrtpExtractionTrace(WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        trace.addTlsAction(
                new SendAction(ATTACKER_TO_SERVER_CONNECTION, new ClientHelloMessage(config)));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.WANT_TO_TEST_SERVER,
                WebRtcProperties.SERVER_NEGOTIATES_SRTP);
    }
}
