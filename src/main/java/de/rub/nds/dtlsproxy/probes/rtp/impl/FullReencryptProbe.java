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
import de.rub.nds.dtlsproxy.probes.rtp.ReencryptProbe;

/**
 * Probe that decrypts, reenccrypts and forwards all DTLS, RTP and RTCP traffic between client and
 * server. A bypass for both parties must be applicable.
 */
public class FullReencryptProbe extends ReencryptProbe {

    public FullReencryptProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext, "FULL RE-ENCRYPT");
    }
}
