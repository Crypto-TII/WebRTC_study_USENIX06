/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.SctpUtil;
import jakarta.xml.bind.DatatypeConverter;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class SctpUtilTest {

    private static final byte[] INIT =
            DatatypeConverter.parseHexBinary(
                    "1388138800000000ec06f7cd0100001e6e54e87f00500000ffffffff01be293ac00000048008000682c00000");

    @Test
    public void testChecksum() {

        byte[] initInvalidChecksum = Arrays.copyOf(INIT, INIT.length);
        initInvalidChecksum[8] = 0x01;
        initInvalidChecksum[9] = 0x01;
        initInvalidChecksum[10] = 0x01;
        initInvalidChecksum[11] = 0x01;

        byte[] res = SctpUtil.updateChecksum(initInvalidChecksum);

        assertArrayEquals(INIT, res);
    }
}
