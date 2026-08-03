/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.DatachannelSetupProbe;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/** Probes whether a client will respond to an SCTP init */
public class ClientDatachannelSetupProbe extends DatachannelSetupProbe {

    public ClientDatachannelSetupProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext, ConnectionEndType.CLIENT);
    }
}
