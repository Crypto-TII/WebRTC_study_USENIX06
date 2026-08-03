/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import org.jitsi.srtp.SrtpPolicy;

public abstract class SrtpPolicyFactory {

    private SrtpPolicyFactory() {}

    public static SrtpPolicy getRtpPolicy(SrtpProtectionProfile srtpProtectionProfile) {

        switch (srtpProtectionProfile) {
            case SRTP_AES128_CM_HMAC_SHA1_80:
                return new SrtpPolicy(
                        SrtpPolicy.AESCM_ENCRYPTION,
                        128 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        80 / 8,
                        112 / 8);
            case SRTP_AES128_CM_HMAC_SHA1_32:
                return new SrtpPolicy(
                        SrtpPolicy.AESCM_ENCRYPTION,
                        128 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        32 / 8,
                        112 / 8);
            case SRTP_NULL_HMAC_SHA1_80:
                return new SrtpPolicy(
                        SrtpPolicy.NULL_ENCRYPTION,
                        0 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        80 / 8,
                        0 / 8);
            case SRTP_NULL_HMAC_SHA1_32:
                return new SrtpPolicy(
                        SrtpPolicy.NULL_ENCRYPTION,
                        0 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        32 / 8,
                        0 / 8);
            case SRTP_AEAD_AES_128_GCM:
                return new SrtpPolicy(
                        SrtpPolicy.AESGCM_ENCRYPTION,
                        128 / 8,
                        SrtpPolicy.NULL_AUTHENTICATION,
                        0 / 8,
                        128 / 8,
                        96 / 8);
            case SRTP_AEAD_AES_256_GCM:
                return new SrtpPolicy(
                        SrtpPolicy.AESGCM_ENCRYPTION,
                        256 / 8,
                        SrtpPolicy.NULL_AUTHENTICATION,
                        0 / 8,
                        128 / 8,
                        96 / 8);
            case SRTP_ARIA_128_CTR_HMAC_SHA1_80: // fall
            case SRTP_ARIA_128_CTR_HMAC_SHA1_32: // fall
            case SRTP_ARIA_256_CTR_HMAC_SHA1_80: // fall
            case SRTP_ARIA_256_CTR_HMAC_SHA1_32: // fall
            case SRTP_AEAD_ARIA_128_GCM: // fall
            case SRTP_AEAD_ARIA_256_GCM: // fall
            case DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM: // fall
            case DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM: // fall
            default:
                throw new RuntimeException("Srtp Policy not implemented");
        }
    }

    public static SrtpPolicy getRtcpPolicy(SrtpProtectionProfile srtpProtectionProfile) {

        switch (srtpProtectionProfile) {
            case SRTP_AES128_CM_HMAC_SHA1_80: // fall
            case SRTP_AES128_CM_HMAC_SHA1_32:
                return new SrtpPolicy(
                        SrtpPolicy.AESCM_ENCRYPTION,
                        128 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        80 / 8,
                        112 / 8);
            case SRTP_NULL_HMAC_SHA1_80: // fall
            case SRTP_NULL_HMAC_SHA1_32:
                return new SrtpPolicy(
                        SrtpPolicy.NULL_ENCRYPTION,
                        0 / 8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION,
                        160 / 8,
                        80 / 8,
                        0 / 8);
            case SRTP_AEAD_AES_128_GCM:
                return new SrtpPolicy(
                        SrtpPolicy.AESGCM_ENCRYPTION,
                        128 / 8,
                        SrtpPolicy.NULL_AUTHENTICATION,
                        0 / 8,
                        128 / 8,
                        96 / 8);
            case SRTP_AEAD_AES_256_GCM:
                return new SrtpPolicy(
                        SrtpPolicy.AESGCM_ENCRYPTION,
                        256 / 8,
                        SrtpPolicy.NULL_AUTHENTICATION,
                        0 / 8,
                        128 / 8,
                        96 / 8);
            case SRTP_ARIA_128_CTR_HMAC_SHA1_80: // fall
            case SRTP_ARIA_128_CTR_HMAC_SHA1_32: // fall
            case SRTP_ARIA_256_CTR_HMAC_SHA1_80: // fall
            case SRTP_ARIA_256_CTR_HMAC_SHA1_32: // fall
            case SRTP_AEAD_ARIA_128_GCM: // fall
            case SRTP_AEAD_ARIA_256_GCM: // fall
            case DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM: // fall
            case DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM: // fall
            default:
                throw new RuntimeException("Srtp Policy not implemented");
        }
    }
}
