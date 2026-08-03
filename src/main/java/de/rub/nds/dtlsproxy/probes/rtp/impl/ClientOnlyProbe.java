/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.SingleSideMediaProbe;

/** Probe that does not contact the server and tries to obtain media from the client */
public class ClientOnlyProbe extends SingleSideMediaProbe {

    public ClientOnlyProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext, "CLIENT ONLY", true);
    }
}
