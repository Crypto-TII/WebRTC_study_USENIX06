/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.enums;

public enum RtcpType {
    SENDER_REPORT((byte) 0xC8),
    RECEIVE_REPORT((byte) 0xC9),
    SOURCE_DESCRIPTION((byte) 0xCA),
    GOODBYE((byte) 0xCB),
    APPLICATION_DEFINED((byte) 0xCC);

    private final byte value;

    private RtcpType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }
}
