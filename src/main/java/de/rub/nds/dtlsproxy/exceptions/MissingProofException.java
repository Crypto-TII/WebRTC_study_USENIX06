/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.exceptions;

public class MissingProofException extends RuntimeException {

    private static final String MESSAGE = "Undecided yet, no proof yet. Reattempting";

    public MissingProofException() {
        super(MESSAGE);
    }

    public MissingProofException(String message) {
        super(message);
    }

    public MissingProofException(String message, Throwable cause) {
        super(message, cause);
    }

    public MissingProofException(Throwable cause) {
        super(MESSAGE, cause);
    }
}
