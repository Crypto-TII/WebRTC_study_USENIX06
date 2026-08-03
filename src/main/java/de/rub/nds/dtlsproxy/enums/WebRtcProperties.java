/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.enums;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;

public enum WebRtcProperties implements AnalyzedProperty {
    /** If the specified connection provider manages to initiate a call / connection */
    PROVIDER_FUNCTIONAL,
    /** If we can start the client and receive a CH */
    CLIENT_FUNCTIONAL,
    /** If we can start the client and receive a SHD from the server */
    SERVER_FUNCTIONAL,
    /** If both, the client and the server can successfully start and be interacted with */
    COMPLETELY_FUNCTIONAL,
    /** Whether the inbound entity was the client */
    INBOUND_WAS_CLIENT_NEGOTIATION,
    /** If we care about the client */
    WANT_TO_TEST_CLIENT,
    /** If we care about the server */
    WANT_TO_TEST_SERVER,

    // Client Hello was coming consistently from the same direction:
    CLIENT_HELLO_DIRECTION_CONSISTENT,
    // The number of different fingerprints in the client hello messages from an inbound connection
    INBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER,
    // The number of different fingerprints in the server hello messages from an inbound connection
    INBOUND_SERVER_HELLO_FINGERPRINT_COUNTER,
    // The number of different fingerprints in the client hello messages from an outbound connection
    OUTBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER,
    // The number of different fingerprints in the server hello messages from an outbound connection
    OUTBOUND_SERVER_HELLO_FINGERPRINT_COUNTER,
    // The number of different server certificate fingerprints from an inbound connection
    INBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER,
    // The number of different server certificate fingerprints from an outbound connection
    OUTBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER,
    // The number of different client certificate fingerprints from an inbound connection
    INBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER,
    // The number of different client certificate fingerprints from an outbound connection
    OUTBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER,

    /**
     * If the client can successfully quit a WebRTC connection and start a new one, possibly without
     * logging in again
     */
    SESSION_RESTART_FUNCTIONAL,

    /** If the server sends a Hello Verify Request */
    SERVER_SENDS_HELLO_VERIFY_REQUEST,
    /** An example cookie the server sends */
    HVR_EXAMPLE_COOKIE,

    CLIENT_SENDS_SNI,

    /** Whether the client includes a session ticket extension in it's ClientHello message */
    CLIENT_SUPPORTS_SESSION_TICKETS,
    /** Whether the client includes an srtp extension in it's ClientHello message */
    CLIENT_NEGOTIATES_SRTP,
    /** Whether the server includes an srtp extension in it's ServerHello message */
    SERVER_NEGOTIATES_SRTP,

    /** SRTP MKI information */
    CLIENT_SENDS_SRTP_MKI,
    EXAMPLE_SRTP_MKI_VALUE,
    SERVER_ACCEPTS_SRTP_MKI_SINGLE_BYTE,
    SERVER_ACCEPTS_SRTP_MKI_TWO_BYTES,
    SERVER_ACCEPTS_SRTP_MKI_THREE_BYTES,
    SERVER_ACCEPTS_SRTP_MKI_FOUR_BYTES,

    /** If the server always presents the same certificate chain */
    STATIC_SERVER_CERTIFICATE,
    /** If the client always presents the same certificate chain */
    STATIC_CLIENT_CERTIFICATE,
    /** If the server is requesting client authentication */
    SERVER_REQUESTS_CERTIFICATE,
    /** If the server accepts any (the tls-attacker default) certificate */
    SERVER_VERIFIES_CERTIFICATE,
    /** If the client accepts any (the tls-attacker default) certificate */
    CLIENT_VERIFIES_CERTIFICATE,
    /** If the client aborts the handshake if no CR is seen */
    CLIENT_ENFORCES_CLIENT_AUTHENTICATION,
    /** If the server rejects the certificate that was provided by the commandline */
    SERVER_REJECTS_PROVIDED_CERTIFICATE,
    /** If the client rejects the certificate that was provided by the commandline */
    CLIENT_REJECTS_PROVIDED_CERTIFICATE,

    /** If the server notices a missing CV */
    SERVER_NOTICES_MISSING_CV,
    /** If the server notices a missing CV and CERT */
    SERVER_NOTICES_MISSING_CERT_CV,
    /**
     * If the server notices a missing CERT message. The CertificateVerify message will either be
     * empty, all 0x00 or all 0xFF
     */
    SERVER_NOTICES_MISSING_CERT_EMPTY_SIGNATURE,
    SERVER_NOTICES_MISSING_CERT_ALL_ZERO_SIGNATURE,
    SERVER_NOTICES_MISSING_CERT_ALL_FF_SIGNATURE,
    /** If the server accepts an empty certificate message */
    SERVER_NOTICES_EMPTY_CERT,
    /** If client authentication can be bypassed by initiating a session resumption before the CV */
    NO_EARLY_RESUMPTION_IDS,

    /** If the client actually verifies the received SKE signatures */
    CLIENT_VERIFIES_SKE_SIGNATURE,
    /** If the client allows for invalid SKE messages without a signature */
    CLIENT_NOTICES_MISSING_SKE_SIGNATURE,
    /** If the server allows for invalid CV messages with an empty signature */
    SERVER_NOTICES_EMPTY_CV_SIGNATURE,
    /** If the serverallows for invalid CV messages without a signature */
    SERVER_NOTICES_MISSING_CV_SIGNATURE,
    /** If the client allows for invalid SKE messages with an empty signature */
    CLIENT_NOTICES_EMPTY_SKE_SIGNATURE,
    /** If the server actually verifies the received CV signature */
    SERVER_VERIFIES_CV_SIGNATURE,
    /** If the client accepts an empty certificate message */
    CLIENT_NOTICES_EMPTY_CERT,
    /** If the server uses a second CKE message after the CV for the key exchange */
    NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_SAME_SQN,
    NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_CONTINUOUS_SQN,

    /**
     * If the client uses a second SKE message for the key exchange without validating the signature
     */
    NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_SAME_SQN,
    NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_CONTINUOUS_SQN,

    /** If the peer rejects a selfsigned certificate that looks like the original one */
    CLIENT_REJECTS_MIMICRY_CERTIFICATE,

    /**
     * If the peer rejects a selfsigned certificate if it is send alongside the valid one (and uses
     * the selfsigned certificate for kex, first we send the attacker cert then the real cert)
     */
    CLIENT_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL,

    /**
     * If the peer rejects a selfsigned certificate if it is send alongside the valid one (and uses
     * the selfsigned certificate for kex, first we send the real cert then the attacker cert)
     */
    CLIENT_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER,

    /**
     * If the peer is rejecting corrupted certificates, i.e. certificates without a signature field
     */
    CLIENT_REJECTS_CORRUPTED_CERTIFICATE,

    /** If the peer rejects a selfsigned certificate */
    SERVER_REJECTS_MIMICRY_CERTIFICATE,
    /**
     * If the peer rejects certificate chains that are very very long, such that the peer loses
     * interest in validating
     */
    SERVER_REJECTS_INVALID_LONG_CHAINS,

    /**
     * If the peer rejects a selfsigned certificate if it is send alongside the valid one (and uses
     * the selfsigned certificate for kex, first we send the attacker cert then the real cert)
     */
    SERVER_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL,

    /**
     * If the peer rejects a selfsigned certificate if it is send alongside the valid one (and uses
     * the selfsigned certificate for kex, first we send the real cert then the attacker cert)
     */
    SERVER_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER,

    /**
     * If the peer is rejecting corrupted certificates, i.e. certificates without a signature field
     */
    SERVER_REJECTS_CORRUPTED_CERTIFICATE,

    /**
     * We try to inject the original client cert after the CV of an attacker connection in the hopes
     * of authenticating as the client.
     */
    SERVER_REJECTS_CERTIFICATE_INJECTION,

    /** Supported Version */
    SERVER_SUPPORTS_DTLS_1_0,
    SERVER_SUPPORTS_DTLS_1_2,
    SERVER_SUPPORTS_DTLS_1_3,
    CLIENT_SUPPORTS_DTLS_1_0,
    CLIENT_SUPPORTS_DTLS_1_2,
    CLIENT_SUPPORTS_DTLS_1_3,

    SERVER_ENFORCES_PICK_ORDER_CIPHER_SUITES,
    SERVER_ENFORCES_PICK_ORDER_NAMED_GROUPS,
    SERVER_ENFORCES_PICK_ORDER_SRTP_PROTECTION_PROFILE,
    SERVER_ENFORCES_PICK_ORDER_SKE_SIG_HASH_ALGORITHMS,

    SERVER_ISSUES_SESSION_IDS,

    /** The server sent an alert when he stopped choosing cipher suites */
    SERVER_CIPHERSUITE_SCAN_TERMINATION_SYMBOL_SEEN,

    /** The server sent an alert when he stopped choosing srtp protection profiles */
    SERVER_SRTP_SCAN_TERMINATION_SYMBOL_SEEN,
    /** The server sent an alert when he stopped choosing signature and hash algorithms */
    SERVER_SIGNATURE_AND_HASH_ALGORITHM_SCAN_TERMINATION_SYMBOL_SEEN,
    /** The server sent an alert when he stopped choosing named groups */
    SERVER_NAMED_GROUP_SCAN_TERMINATION_SYMBOL_SEEN,
    /** The server answers a DTLS encrypted SCTP-INIT */
    SERVER_RESPONDS_TO_SCTP_INIT,
    /** The client answers a DTLS encrypted SCTP-INIT */
    CLIENT_RESPONDS_TO_SCTP_INIT,
    /**
     * The server responds with a Serve Hello to an encrypted Client Hello after the initial
     * handshake was completed
     */
    SERVER_ALLOWS_RENEGOTIATION,
    /** Whether an alert is received from a peer after completing a DTLS handshake using a bypass */
    BYPASS_PRODUCED_ALERT;

    @Override
    public AnalyzedPropertyCategory getCategory() {
        return null;
    }

    @Override
    public String getName() {
        return this.name();
    }
}
