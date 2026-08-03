/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.webex;

import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.RtcChannel;

public class WebexRtcChannel extends RtcChannel {

    private boolean mediaRequestReceived = false;
    private boolean allSourceAdsReceived = false;

    public boolean isMediaRequestReceived() {
        return mediaRequestReceived;
    }

    public void setMediaRequestReceived(boolean mediaRequestReceived) {
        this.mediaRequestReceived = mediaRequestReceived;
    }

    public boolean isAllSourceAdsReceived() {
        return allSourceAdsReceived;
    }

    public void setAllSourceAdsReceived(boolean allSourceAdsReceived) {
        this.allSourceAdsReceived = allSourceAdsReceived;
    }
}
