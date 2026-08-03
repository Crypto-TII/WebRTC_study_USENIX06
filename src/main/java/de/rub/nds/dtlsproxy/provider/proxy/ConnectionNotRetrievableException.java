/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

/** Indicating that it was deemed impossible to retrieve a connection from the current session */
public class ConnectionNotRetrievableException extends RuntimeException {

    public ConnectionNotRetrievableException(String message) {
        super(message);
    }
}
