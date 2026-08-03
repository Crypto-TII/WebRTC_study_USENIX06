/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.report;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.enums.MitmProperties;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass.AuthBypass;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import java.util.HashMap;
import java.util.Map;

public class MediaReport {

    private Map<MediaProtocol, Map<MitmProperties, TestResults>> resultsclientToServer =
            new HashMap<>();
    private Map<MediaProtocol, Map<MitmProperties, TestResults>> resultsserverToClient =
            new HashMap<>();
    private Map<WebRtcProperties, DetailedResult<String>> additionalResults = new HashMap<>();

    private final String label;

    private boolean testable;

    private boolean dtlsHandshakeSuccess = true;

    private AuthBypass bypassUsed;

    public MediaReport(String label) {
        this.label = label;
        this.testable = true;
    }

    private void setResult(
            Map<MediaProtocol, Map<MitmProperties, TestResults>> map,
            MediaProtocol mediaProtocol,
            MitmProperties property,
            TestResults result) {

        if (!map.containsKey(mediaProtocol)) {
            map.put(mediaProtocol, new HashMap<>());
        }

        map.get(mediaProtocol).put(property, result);
    }

    public void setResult(
            MediaProtocol mediaProtocol,
            MitmProperties property,
            TestResults result,
            boolean clientToServer) {

        if (clientToServer) {
            setResult(resultsclientToServer, mediaProtocol, property, result);
        } else {
            setResult(resultsserverToClient, mediaProtocol, property, result);
        }
    }

    public void setResult(
            MediaProtocol mediaProtocol,
            MitmProperties property,
            boolean result,
            boolean clientToServer) {
        setResult(
                mediaProtocol,
                property,
                result ? TestResults.TRUE : TestResults.FALSE,
                clientToServer);
    }

    public String getLabel() {
        return label;
    }

    public boolean isTestable() {
        return testable;
    }

    public void setTestable(boolean testable) {
        this.testable = testable;
    }

    public Map<MediaProtocol, Map<MitmProperties, TestResults>> getResultsClientToServer() {
        return resultsclientToServer;
    }

    public Map<MediaProtocol, Map<MitmProperties, TestResults>> getResultsServerToClient() {
        return resultsserverToClient;
    }

    public boolean isDtlsHandshakeSuccess() {
        return dtlsHandshakeSuccess;
    }

    public void setDtlsHandshakeSuccess(boolean dtlsHandshakeSuccess) {
        this.dtlsHandshakeSuccess = dtlsHandshakeSuccess;
    }

    public AuthBypass getBypassUsed() {
        return bypassUsed;
    }

    public void setBypassUsed(AuthBypass bypassUsed) {
        this.bypassUsed = bypassUsed;
    }

    public Map<WebRtcProperties, DetailedResult<String>> getAdditionalResults() {
        return additionalResults;
    }

    public void putAdditionalResult(WebRtcProperties property, DetailedResult<String> result) {
        additionalResults.put(property, result);
    }
}
