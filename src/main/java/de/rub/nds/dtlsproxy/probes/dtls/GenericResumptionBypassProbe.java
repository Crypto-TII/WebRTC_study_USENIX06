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
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.util.List;

public class GenericResumptionBypassProbe extends DtlsProbe {

    public GenericResumptionBypassProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        /**
         * What we want to test here is if we can resume a connection the attacker initiated with
         * his account using a different account on a peer opened session. We would expect this to
         * work if all connections share a resumption pool and the certificate of the peer is not
         * checked again on the application layer
         */
        throw new UnsupportedOperationException(
                "For this we need access to the cert and private key of a real client");
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getRequiredProperties'");
    }
}
