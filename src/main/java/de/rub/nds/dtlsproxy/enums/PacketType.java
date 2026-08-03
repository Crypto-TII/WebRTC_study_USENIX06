/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.enums;

public enum PacketType {
    DTLS_HANDSHAKE,
    DTLS_APP_DATA,
    DTLS_ALERT,
    DTLS_CHANGE_CIPHER_SPEC,
    DTLS_MISC,
    RTP,
    RTCP,
    STUN,
    ZRTP,
    QUIC,
    TURN_CHANNEL,
    UNKNOWN
}
