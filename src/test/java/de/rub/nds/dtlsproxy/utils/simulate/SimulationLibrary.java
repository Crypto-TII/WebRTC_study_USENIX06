/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import de.rub.nds.dtlsproxy.utils.PacketLibrary;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SimulationLibrary {

    private static final int INDEX_SEPERATOR = 100;

    /** Index range of all data send with a client hello, as well as the CH itself */
    public static final int INDEX_ID_CH = 0 * INDEX_SEPERATOR;

    /** Index range of all data send with a server hello, as well as the SH itself */
    public static final int INDEX_ID_SH = 1 * INDEX_SEPERATOR;

    /** Index range of all data send with a client key exchange, as well as the CKEX itself */
    public static final int INDEX_ID_CKEX = 2 * INDEX_SEPERATOR;

    /**
     * Index range of all data send with a (server) change cipher spec, as well as the CCS itself
     */
    public static final int INDEX_ID_SCCS = 3 * INDEX_SEPERATOR;

    /** Index range of all data send with a finished message, as well as the message itself */
    public static final int INDEX_ID_CA = 4 * INDEX_SEPERATOR;

    /** Simulates a full DTLS Handshake (taken from Discord) */
    public static final List<SimulatedAction> FULL_HS;

    /** Simulates a full DTLS Handshake, missing a Certificate Request (taken from Zoom) */
    public static final List<SimulatedAction> FULL_HS_NO_CR;

    /** Simulates a full DTLS Handshake, client side only (taken from Discord) */
    public static final List<SimulatedAction> FULL_HS_CLIENT_SIDE;

    /** Simulates a full DTLS Handshake, CH and server side only (taken from Discord) */
    public static final List<SimulatedAction> FULL_HS_SERVER_SIDE;

    static {
        FULL_HS =
                Arrays.asList(
                        action(
                                INDEX_ID_CH,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_HELLO_3,
                                "client hello"),
                        action(
                                INDEX_ID_SH,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS,
                                "server hello"),
                        action(
                                INDEX_ID_SH + 1,
                                ConnectionSide.SERVER,
                                PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_2,
                                "server hello cont"),
                        action(
                                INDEX_ID_CKEX,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_3,
                                "client kex"),
                        action(
                                INDEX_ID_SCCS,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_SESSION_TICKET_CCS_3,
                                "server ccs"),
                        action(
                                INDEX_ID_CA,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_ENC_ALERT_5,
                                "enc alert"));

        FULL_HS_NO_CR =
                Arrays.asList(
                        action(
                                INDEX_ID_CH,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_HELLO_4,
                                "client hello"),
                        action(
                                INDEX_ID_SH,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_NO_CR_4_0,
                                "server hello"),
                        action(
                                INDEX_ID_CKEX,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_NO_CR_4_1,
                                "server hello cont"),
                        action(
                                INDEX_ID_CKEX + 1,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_NO_CR_4_2,
                                "server hello cont"),
                        action(
                                INDEX_ID_CKEX + 2,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_NO_CR_4_3,
                                "server hello cont"),
                        action(
                                INDEX_ID_CKEX + 3,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_NO_CR_4_4,
                                "server hello cont"),
                        action(
                                INDEX_ID_SCCS,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_4,
                                "client kex"),
                        action(
                                INDEX_ID_CA,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_SESSION_TICKET_CCS_4,
                                "server ccs"));

        FULL_HS_CLIENT_SIDE =
                Arrays.asList(
                        action(
                                INDEX_ID_CH,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_HELLO_3,
                                "client hello"),
                        action(
                                INDEX_ID_CKEX,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_3,
                                "client kex"),
                        action(
                                INDEX_ID_CA,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_ENC_ALERT_5,
                                "enc alert"));

        FULL_HS_SERVER_SIDE =
                Arrays.asList(
                        action(
                                INDEX_ID_CH,
                                ConnectionSide.CLIENT,
                                PacketLibrary.CLIENT_HELLO_3,
                                "client hello"),
                        action(
                                INDEX_ID_SH,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS,
                                "server hello"),
                        action(
                                INDEX_ID_SH + 1,
                                ConnectionSide.SERVER,
                                PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_2,
                                "server hello cont"),
                        action(
                                INDEX_ID_SCCS,
                                ConnectionSide.SERVER,
                                PacketLibrary.SERVER_SESSION_TICKET_CCS_3,
                                "server ccs"));
    }

    private SimulationLibrary() {}

    private static SimulatedAction action(
            int index, ConnectionSide side, byte[] udpPayload, String name) {
        return new SimulatedAction(index, side, udpPayload, name);
    }

    public static List<SimulatedAction> remove(
            final List<SimulatedAction> actions, int... indexIds) {

        ArrayList<SimulatedAction> res = new ArrayList<>(actions);

        for (int indexId : indexIds) {
            for (SimulatedAction action : actions) {
                if (action.getTimeIndex() / INDEX_SEPERATOR == indexId / INDEX_SEPERATOR)
                    res.remove(action);
            }
        }

        return res;
    }
}
