/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public interface RtpCrypto {

    public static final int BUFFER_SIZE = 2048;

    public SrtpErrorStatus decryptSrtp(ByteArrayBuffer srtpPacket);

    public SrtpErrorStatus encryptSrtp(ByteArrayBuffer rtpPacket);

    public SrtpErrorStatus decryptSrtcp(ByteArrayBuffer srtcpPacket);

    public SrtpErrorStatus encryptSrtcp(ByteArrayBuffer rtcpPacket);
}
