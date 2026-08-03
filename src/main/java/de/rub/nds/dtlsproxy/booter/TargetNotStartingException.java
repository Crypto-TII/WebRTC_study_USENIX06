/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

public class TargetNotStartingException extends RuntimeException {
    public TargetNotStartingException(String message) {
        super(message);
    }

    public TargetNotStartingException(String message, Exception exception) {
        super(message, exception);
    }
}
