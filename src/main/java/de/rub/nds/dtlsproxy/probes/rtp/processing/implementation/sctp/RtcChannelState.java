/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp;

public enum RtcChannelState {
    INITIAL,

    AWAIT_INIT_ACK,

    AWAIT_COOKIE_ACK,

    POST_HANDSHAKE
}
