/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class ForwardServerFlightActionTest {

    @Test
    public void testGettersAndSetters() {
        ForwardServerFlightAction action = new ForwardServerFlightAction();
        String receiveFromAlias = "receiveFromAlias";
        String forwardToAlias = "forwardToAlias";

        // Test the setters
        action.setReceiveFromAlias(receiveFromAlias);
        action.setForwardToAlias(forwardToAlias);

        // Test the getters
        assertEquals(receiveFromAlias, action.getReceiveFromAlias());
        assertEquals(forwardToAlias, action.getForwardToAlias());
    }
}
