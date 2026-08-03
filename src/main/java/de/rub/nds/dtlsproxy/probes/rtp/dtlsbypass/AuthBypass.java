/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public abstract class AuthBypass {

    protected static final String ATTACKER_TO_SERVER_CONNECTION = "attackerToClient";
    protected static final String CLIENT_TO_ATTACKER_CONNECTION = "clientToAttacker";

    private final String description;
    private final boolean bypassesServerAuth;
    private final boolean bypassesClientAuth;

    public AuthBypass(String description, boolean bypassesServerAuth, boolean bypassesClientAuth) {
        this.description = description;
        this.bypassesServerAuth = bypassesServerAuth;
        this.bypassesClientAuth = bypassesClientAuth;
    }

    public abstract WorkflowTrace createTrace(
            WebRtcPlatformReport report, ProxyConfiguration proxyConfiguration);

    public abstract boolean isApplicable(WebRtcPlatformReport report);

    public String getDescription() {
        return description;
    }

    public boolean isBypassesServerAuth() {
        return bypassesServerAuth;
    }

    public boolean isBypassesClientAuth() {
        return bypassesClientAuth;
    }

    protected static boolean basicExecutionRequirementsMet(WebRtcPlatformReport report) {
        if (report.getResult(WebRtcProperties.COMPLETELY_FUNCTIONAL) != TestResults.TRUE) {
            return false;
        }
        return true;
    }

    protected static boolean isTrue(WebRtcPlatformReport report, WebRtcProperties property) {

        if (report.getResult(property) == null) {
            return false;
        }

        if (report.getResult(property) instanceof DetailedResult) {
            DetailedResult<String> result = (DetailedResult) report.getResult(property);
            return result.getSummarizedResult().equals(TestResults.TRUE);
        }

        return report.getResult(property) == TestResults.TRUE;
    }

    protected static boolean isFalse(WebRtcPlatformReport report, WebRtcProperties property) {

        if (report.getResult(property) == null) {
            return false;
        }

        if (report.getResult(property) instanceof DetailedResult) {
            DetailedResult<String> result = (DetailedResult) report.getResult(property);
            return result.getSummarizedResult().equals(TestResults.FALSE);
        }

        return report.getResult(property) == TestResults.FALSE;
    }

    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {
        return TraceUtil.applyRtpConfig(
                TraceUtil.getFunctionalConfig(
                        configuration,
                        report,
                        this.getClientToAttackerConnectionAlias(),
                        this.getAttackerToServerConnectionAlias()));
    }

    public String getAttackerToServerConnectionAlias() {
        return ATTACKER_TO_SERVER_CONNECTION;
    }

    public String getClientToAttackerConnectionAlias() {
        return CLIENT_TO_ATTACKER_CONNECTION;
    }
}
