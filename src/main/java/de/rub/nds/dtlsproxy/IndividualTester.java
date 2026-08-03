/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy;

import de.rub.nds.dtlsproxy.probes.Probe;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.dtls.*;
import de.rub.nds.dtlsproxy.probes.rtp.impl.*;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IndividualTester {

    private static final Logger LOGGER = LogManager.getLogger();

    private WebrtcExecutionContext webrtcExecutionContext;

    public IndividualTester(WebrtcExecutionContext webrtcExecutionContext) {
        this.webrtcExecutionContext = webrtcExecutionContext;
    }

    public WebRtcPlatformReport performTest() {
        LOGGER.info("-->Testing {}", webrtcExecutionContext.getPlatformReport().getTargetName());
        webrtcExecutionContext
                .getConnectionProvider()
                .lockInFilterDirection(
                        webrtcExecutionContext.getPlatformReport().getLockedFilterDirection());
        List<Probe> testList = createTestList(webrtcExecutionContext);
        LOGGER.debug(
                "Executing probe list: \n\t{}",
                testList.stream()
                        .map(p -> p.getClass().getSimpleName())
                        .collect(Collectors.joining("\n\t")));
        for (Probe test : testList) {
            if (test.isTestApplicable(webrtcExecutionContext.getPlatformReport())) {
                LOGGER.debug("Initiating Test: {}", test.getClass().getSimpleName());
                test.test(webrtcExecutionContext.getPlatformReport());
            } else {
                LOGGER.debug(
                        "Skipping Test {}, as deemed not applicable",
                        test.getClass().getSimpleName());
            }
        }
        webrtcExecutionContext
                .getPlatformReport()
                .setConnectionCreationReport(
                        webrtcExecutionContext
                                .getConnectionProvider()
                                .getConnectionCreationReport());
        webrtcExecutionContext.getPostAnalyzer().finalizeReport();
        return webrtcExecutionContext.getPlatformReport();
    }

    private List<Probe> createTestList(WebrtcExecutionContext webrtcExecutionContext) {
        List<Probe> testList = new LinkedList<>();

        // DTLS Handshake probes
        testList.add(new NonMitmConnectionsProbe(webrtcExecutionContext));
        testList.add(new SelfTestProbe(webrtcExecutionContext));
        testList.add(new ProtocolVersionProbe(webrtcExecutionContext));
        testList.add(new ServerCipherSuiteProbe(webrtcExecutionContext));
        testList.add(new ServerSrtpProtectionProfileProbe(webrtcExecutionContext));
        testList.add(new ServerSkeSignatureAndHashAlgorithmsProbe(webrtcExecutionContext));
        testList.add(new StaticCertificateProbe(webrtcExecutionContext));
        testList.add(new ClientVerifiesCertificatesProbe(webrtcExecutionContext));
        testList.add(new ServerVerifiesCertificatesProbe(webrtcExecutionContext));
        testList.add(new ClientEnforcesAuthenticationProbe(webrtcExecutionContext));
        testList.add(new ServerNamedGroupsProbe(webrtcExecutionContext));
        testList.add(new MissingMessageServerProbe(webrtcExecutionContext));
        testList.add(new EarlyResumptionAuthBypassProbe(webrtcExecutionContext));
        testList.add(new SignatureVerificationProbe(webrtcExecutionContext));
        testList.add(new DoubleCkeProcessingProbe(webrtcExecutionContext));
        testList.add(new DoubleSkeProcessingProbe(webrtcExecutionContext));
        testList.add(new EmptyServerCertificateProbe(webrtcExecutionContext));
        testList.add(new ClientCertificateAcceptanceProbe(webrtcExecutionContext));
        testList.add(new ServerCertificateAcceptanceProbe(webrtcExecutionContext));

        // Media / Post DTLS probes
        testList.add(new ClientOnlyProbe(webrtcExecutionContext));
        testList.add(new ServerOnlyProbe(webrtcExecutionContext));
        testList.add(new FullReencryptProbe(webrtcExecutionContext));
        testList.add(new RenegotiateReencryptProbe(webrtcExecutionContext));
        testList.add(new ClientDatachannelSetupProbe(webrtcExecutionContext));
        testList.add(new ServerDatachannelSetupProbe(webrtcExecutionContext));
        testList.add(new BypassesProducesAlertProbe(webrtcExecutionContext));
        return testList;
    }
}
