/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.enums;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;

public enum MitmProperties implements AnalyzedProperty {
    DATA_RECEIVED("Received data from endpoint"),
    DECRYPTION_SUCCESS("Successfully decrypted data from endpoint"),
    ENCRYPTION_SUCCESS("Successfully re-encrypted data from endpoint");

    private final String description;

    private MitmProperties(String description) {
        this.description = description;
    }

    @Override
    public AnalyzedPropertyCategory getCategory() {
        return null;
    }

    public String getName() {
        return description;
    }
}
