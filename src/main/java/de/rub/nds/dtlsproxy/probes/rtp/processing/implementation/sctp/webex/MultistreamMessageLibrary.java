/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.webex;

public final class MultistreamMessageLibrary {

    public static final String MEDIA_REQUEST_AUDIO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"mediaRequest\",\"payload\":{\"seqNum\":1,\"requests\":[{\"policy\":\"active-speaker\",\"policySpecificInfo\":{\"priority\":255,\"crossPriorityDuplication\":false,\"crossPolicyDuplication\":false,\"preferLiveVideo\":false},\"ids\":[{\"ssrc\":XXSSRC1XX},{\"ssrc\":XXSSRC2XX},{\"ssrc\":XXSSRC3XX}],\"maxPayloadBitsPerSecond\":64000,\"codecInfos\":[]}]}}}}";
    public static final String MEDIA_REQUEST_AUDIO_SLIDES =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"SLIDES\",\"payload\":{\"msgType\":\"mediaRequest\",\"payload\":{\"seqNum\":1,\"requests\":[{\"policy\":\"active-speaker\",\"policySpecificInfo\":{\"priority\":255,\"crossPriorityDuplication\":false,\"crossPolicyDuplication\":false,\"preferLiveVideo\":false},\"ids\":[{\"ssrc\":XXSSRC1XX}],\"maxPayloadBitsPerSecond\":64000,\"codecInfos\":[]}]}}}}";
    public static final String MEDIA_REQUEST_VIDEO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"VIDEO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"mediaRequest\",\"payload\":{\"seqNum\":1,\"requests\":[]}}}}";
    public static final String MEDIA_REQUEST_VIDEO_SLIDES =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"VIDEO\",\"mediaContent\":\"SLIDES\",\"payload\":{\"msgType\":\"mediaRequest\",\"payload\":{\"seqNum\":1,\"requests\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_VIDEO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"VIDEO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":1,\"numTotalSources\":1,\"numLiveSources\":0,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_AUDIO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":1,\"numTotalSources\":1,\"numLiveSources\":0,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_AUDIO_MAIN_3 =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":3,\"numTotalSources\":1,\"numLiveSources\":0,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_AUDIO_MAIN_4 =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":4,\"numTotalSources\":1,\"numLiveSources\":1,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_VIDEO_SLIDES =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"VIDEO\",\"mediaContent\":\"SLIDES\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":1,\"numTotalSources\":1,\"numLiveSources\":0,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_AUDIO_SLIDES =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"SLIDES\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":1,\"numTotalSources\":1,\"numLiveSources\":0,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_AUDIO_MAIN_ACTIVE =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisement\",\"payload\":{\"seqNum\":2,\"numTotalSources\":1,\"numLiveSources\":1,\"namedMediaGroups\":[]}}}}";
    public static final String SOURCE_ADVERTISEMENT_ACKNOWLEDGMENT_AUDIO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"sourceAdvertisementAck\",\"payload\":{\"sourceAdvertisementSeqNum\":XXACKSQNXX}}}}";
    public static final String MEDIA_REQUEST_ACKNOWLEDGMENT_AUDIO_MAIN =
            "{\"msgType\":\"multistream\",\"payload\":{\"mediaFamily\":\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"mediaRequestAck\",\"payload\":{\"mediaRequestSeqNum\":XXACKSQNXX}}}}";

    private MultistreamMessageLibrary() {}
}
