/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp;

public class RtcChannel {

    private RtcChannelState state = RtcChannelState.INITIAL;
    private int initiateTag;
    private byte[] cookie;
    private int cookieLengthParameter;
    private byte[] verificationTag;
    private int dataPacketsReceived = 0;
    private int dataPacketsSend = 0;
    private int nextTsn = 0;
    private short nextSsn = 0;

    public RtcChannelState getState() {
        return state;
    }

    public void setState(RtcChannelState state) {
        this.state = state;
    }

    public int getInitiateTag() {
        return initiateTag;
    }

    public void setInitiateTag(int initiateTag) {
        this.initiateTag = initiateTag;
    }

    public byte[] getCookie() {
        return cookie;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = cookie;
    }

    public int getCookieLengthParameter() {
        return cookieLengthParameter;
    }

    public void setCookieLengthParameter(int cookieLengthParameter) {
        this.cookieLengthParameter = cookieLengthParameter;
    }

    public byte[] getVerificationTag() {
        return verificationTag;
    }

    public void setVerificationTag(byte[] verificationTag) {
        this.verificationTag = verificationTag;
    }

    public int getDataPacketsReceived() {
        return dataPacketsReceived;
    }

    public void setDataPacketsReceived(int dataPacketsReceived) {
        this.dataPacketsReceived = dataPacketsReceived;
    }

    public int getDataPacketsSend() {
        return dataPacketsSend;
    }

    public void setDataPacketsSend(int dataPacketsSend) {
        this.dataPacketsSend = dataPacketsSend;
    }

    public void incrementPacketsSend() {
        this.dataPacketsSend++;
    }

    public void incrementPacketsReceived() {
        this.dataPacketsReceived++;
    }

    public int getNextTsn() {
        return nextTsn;
    }

    public void setNextTsn(int nextTsn) {
        this.nextTsn = nextTsn;
    }

    public void incrementTsn() {
        this.nextTsn = this.nextTsn + 1;
    }

    public short getNextSsn() {
        return nextSsn;
    }

    public void setNextSsn(short nextSsn) {
        this.nextSsn = nextSsn;
    }

    public void incrementSsn() {
        this.nextSsn = (short) (this.nextSsn + 1);
    }
}
