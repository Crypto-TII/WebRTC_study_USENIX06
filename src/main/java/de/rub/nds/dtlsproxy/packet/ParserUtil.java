/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.packet;

import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.enums.RtcpType;
import de.rub.nds.dtlsproxy.provider.StunAddress;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.util.ReadOnlyTransportHandler;
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.ice.model.StunAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.ice.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.core.ice.parser.StunMessageParser;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.JaFingerprintCalculator;
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ParserUtil {

    private static final State STUN_PARSING_STATE = new State(new Config());
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String TLS_ATTACKER_PARSING_CONNECTION_ALIAS = "default";

    /**
     * returns the type of last protocol layer found in the given data by traversing TURN layers
     *
     * @param data packet
     * @return packet type detected
     */
    public static PacketType classifyLastLayer(byte[] data) {
        List<PacketType> layers = classifyLayers(data);
        return layers.get(layers.size() - 1);
    }

    /**
     * traverses TURN layers and returns the protocol layers discovered when doing so
     *
     * @param data packet
     * @param layersSoFar list of lower layers discovered so far and not included in the packet
     * @return list of additionally discovered layers
     */
    private static List<PacketType> classifyLayers(byte[] data, List<PacketType> layersSoFar) {
        try {
            // check if DTLS used
            if (isDtls(data)) {
                layersSoFar.add(getDtlsType(data));
                return layersSoFar;
            }

            // check if STUN is used
            if (isStun(data)) {
                // check if data encapsulated
                byte[] dataEncapsulated = carriesStunDataExtension(data);
                layersSoFar.add(PacketType.STUN);
                if (dataEncapsulated == null) {
                    // No data encapsulated
                    return layersSoFar;
                }
                // recursive check what is encapsulated
                return classifyLayers(dataEncapsulated, layersSoFar);
            }

            if (isTurnChannelMessage(data)) {
                layersSoFar.add(PacketType.TURN_CHANNEL);
                // recursive check what is encapsulated
                byte[] dataEncapsulated = Arrays.copyOfRange(data, 4, data.length);
                return classifyLayers(dataEncapsulated, layersSoFar);
            }

            if (isRtp(data)) {
                layersSoFar.add(PacketType.RTP);
                return layersSoFar;
            }

            if (isRtcp(data)) {
                layersSoFar.add(PacketType.RTCP);
                return layersSoFar;
            }

            layersSoFar.add(PacketType.UNKNOWN);
        } catch (ParserException e) {
            LOGGER.trace("Failed to parse packet: {}", data, e);
            if (layersSoFar.isEmpty()) {
                layersSoFar.add(PacketType.UNKNOWN);
            }
        }
        return layersSoFar;
    }

    /**
     * traverses TURN layers and returns the protocol layers discovered when doing so
     *
     * @param data packet
     * @return list of discovered layers
     */
    public static List<PacketType> classifyLayers(byte[] data) {
        List<PacketType> layersSoFar = new ArrayList<>();
        return classifyLayers(data, layersSoFar);
    }

    /**
     * This is some rudimentary detection of DTLS frames. DTLS records should be atleast 5 bytes
     * long. The first byte should be the protocol message type, which we ignore for now (we could
     * check that the type is plausible) and the second byte should be 0xFE (DTLS version 1.0/12)
     * and the third byte should be 0xFF (DTLS version 1.0) or FD (DTLS version 1.2)
     *
     * @param data Data to look for DTLS in
     * @return True if the data is a DTLS frame, false otherwise
     */
    public static boolean isDtls(byte[] data) {
        boolean firstCheck =
                data.length > 5
                        && (data[1] & 0xff) == 0xFE
                        && ((data[2] & 0xff) == 0xFF || (data[2] & 0xff) == 0xFD);
        if (firstCheck) {
            for (ProtocolMessageType type : ProtocolMessageType.values()) {
                if (type.getValue() == (data[0] & 0xff)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Assumes given a STUN packet given as input and checks if a data extention present. Will
     * return the data payload of the extention if present, null otherwise
     *
     * @param data STUN package
     * @return encapsulated data, null if no data found
     */
    public static byte[] carriesStunDataExtension(byte[] data) {
        StunMessage message = parseStunMessage(data);
        if (message == null) {
            // not stun data
            return null;
        }
        for (StunAttribute attribute : message.getAttributeList()) {
            if (attribute.getType() == StunAttributeType.DATA) {
                return attribute.getBody().getValue();
            }
        }
        // No Data attribute found
        return null;
    }

    /**
     * Checks if data is sorted to Stun after multiplexing
     *
     * @param data Data to look for stun in
     * @return True if the data is a stun frame, false otherwise
     */
    public static boolean isStun(byte[] data) {
        return classify(data, true) == PacketType.STUN;
    }

    /**
     * Checks if data is sorted to RTP after multiplexing
     *
     * @param data
     * @return false if no RTP, true if assumed RTP
     */
    public static boolean isRtp(byte[] data) {
        return classify(data, true) == PacketType.RTP;
    }

    /**
     * Checks if data is sorted to RTCP after multiplexing
     *
     * @param data
     * @return false if no RTCP, true if assumed RTCP
     */
    public static boolean isRtcp(byte[] data) {
        return classify(data, true) == PacketType.RTCP;
    }

    /**
     * Checks if data is sorted to TURN Channel after multiplexing
     *
     * @param data
     * @return false if no Turn Channel Message, true if assumed Turn Channel Message
     */
    public static boolean isTurnChannelMessage(byte[] data) {
        return classify(data, true) == PacketType.TURN_CHANNEL;
    }

    public static RtcpType getRtcpType(byte[] data) {
        if (data.length < 10) {
            return null;
        }
        if ((data[1] & 0xff) == RtcpType.SENDER_REPORT.getValue()) {
            return RtcpType.SENDER_REPORT;
        }
        if ((data[1] & 0xff) == RtcpType.RECEIVE_REPORT.getValue()) {
            return RtcpType.RECEIVE_REPORT;
        }
        if ((data[1] & 0xff) == RtcpType.SOURCE_DESCRIPTION.getValue()) {
            return RtcpType.SOURCE_DESCRIPTION;
        }
        if ((data[1] & 0xff) == RtcpType.GOODBYE.getValue()) {
            return RtcpType.GOODBYE;
        }
        if ((data[1] & 0xff) == RtcpType.APPLICATION_DEFINED.getValue()) {
            return RtcpType.APPLICATION_DEFINED;
        }
        return null;
    }

    public static PacketType getDtlsType(byte[] data) {
        if (ProtocolMessageType.ALERT.getValue() == (data[0] & 0xff)) {
            return PacketType.DTLS_ALERT;
        }
        if (ProtocolMessageType.HANDSHAKE.getValue() == (data[0] & 0xff)) {
            return PacketType.DTLS_HANDSHAKE;
        }
        if (ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue() == (data[0] & 0xff)) {
            return PacketType.DTLS_CHANGE_CIPHER_SPEC;
        }
        if (ProtocolMessageType.APPLICATION_DATA.getValue() == (data[0] & 0xff)) {
            return PacketType.DTLS_APP_DATA;
        }
        return PacketType.DTLS_MISC;
    }

    /** Determines the first protocol used in byte array given, in accordance with rfc9443. */
    public static PacketType classify(byte[] data, boolean expectTurn) {

        int firstByte = Byte.toUnsignedInt(data[0]);

        if (firstByte >= 0 && firstByte <= 3) {
            return PacketType.STUN;
        } else if (firstByte >= 16 && firstByte <= 19) {
            return PacketType.ZRTP;
        } else if (firstByte >= 20 && firstByte <= 63) {
            return getDtlsType(data);
        } else if (firstByte >= 128 && firstByte <= 191) {
            // possible rtp or rtcp

            // check rtcp types
            if ((data[1] & 0xff) == 0xc8) { // sender report
                return PacketType.RTCP;
            } else if ((data[1] & 0xff) == 0xc9) { // receiver report
                return PacketType.RTCP;
            } else if ((data[1] & 0xff) == 0xca) { // sdes
                return PacketType.RTCP;
            } else if ((data[1] & 0xff) == 0xcb) { // goodbye
                return PacketType.RTCP;
            } else if ((data[1] & 0xff) == 0xcc) { // app-defined
                return PacketType.RTCP;
            }

            // check if extension bit set and extension header found
            if ((data[0] & 0x10) == 0x10) { // ext set
                if (data.length > 14 && (data[12] & 0xff) == 0xBE && (data[13] & 0xff) == 0xDE) {
                    return PacketType.RTP;
                } else {
                    return PacketType.UNKNOWN;
                }
            } else { // ext not set
                if (data.length > 14 && (data[12] & 0xff) == 0xBE && (data[13] & 0xff) == 0xDE) {
                    return PacketType.UNKNOWN;
                } else {
                    return PacketType.RTP;
                }
            }

        } else if ((firstByte >= 80 && firstByte <= 127)
                || (firstByte >= 192 && firstByte <= 255)) {
            return PacketType.QUIC;
        } else if (firstByte >= 64 && firstByte <= 79) {
            if (expectTurn) {
                return PacketType.TURN_CHANNEL;
            } else {
                return PacketType.QUIC;
            }
        } else {
            return PacketType.UNKNOWN;
        }
    }

    public static StunAddress parseStunAddress(byte[] rawData) throws UnknownHostException {
        if (ParserUtil.isStun(rawData)) {
            StunMessage message = parseStunMessage(rawData);
            for (StunAttribute attribute : message.getAttributeList()) {
                if (attribute.getType() == StunAttributeType.XOR_PEER_ADDRESS) {
                    XorPeerAddressAttribute xorPeerAddressAttribute =
                            (XorPeerAddressAttribute) attribute;
                    LOGGER.debug(
                            "Found TURN peer (mapped) address: {}:{}",
                            InetAddress.getByAddress(
                                    xorPeerAddressAttribute.getIpAddress().getValue()),
                            xorPeerAddressAttribute.getPort().getValue());
                    return new StunAddress(
                            xorPeerAddressAttribute.getIpAddress().getValue(),
                            xorPeerAddressAttribute.getPort().getValue());
                }
            }
            LOGGER.warn("Could not find peer address");
            return null; // No peer address found
        } else {
            return null;
        }
    }

    public static String getClientHelloJA3(HookedConnection connection) {

        byte[] dtlsFromClientSoFar = getHandshakeUdpFromClient(connection);

        if (dtlsFromClientSoFar.length == 0) {
            throw new RuntimeException(
                    "Can not create JA3 fingerprint: no dtls data in connection");
        }

        ClientHelloMessage clientHelloMessage =
                parseHandshakeMessage(
                        dtlsFromClientSoFar, connection.isUsingTurn(), new ClientHelloMessage());

        if (clientHelloMessage == null) {
            throw new RuntimeException(
                    "Can not create JA3 Fingerprint: Client hello parsing failed (data incomplete?)");
        }

        return JaFingerprintCalculator.getJa3FingerprintString(clientHelloMessage);
    }

    public static StunMessage parseStunMessage(byte[] rawData) {
        // We need to remember the mapped address
        try {

            StunMessageParser parser =
                    new StunMessageParser(
                            STUN_PARSING_STATE.getContext(), new ByteArrayInputStream(rawData));
            if (rawData.length < 2) {
                return null;
            } else {
                byte[] typeBytes = Arrays.copyOfRange(rawData, 0, IceByteLengths.STUN_MESSAGE_TYPE);
                StunMethodType methodType = StunMethodType.getStunMethodTypeFromRawBytes(typeBytes);
                StunMessageClass messageClass = StunMessageClass.getMessageClass(typeBytes);
                StunMessage message = new StunMessage(messageClass, methodType);
                parser.parse(message);
                message.getPreparator(STUN_PARSING_STATE.getContext())
                        .prepareAfterParse(); // Decode IP and Port
                return message;
            }

        } catch (EndOfStreamException E) {
            throw new ParserException(E);
        }
    }

    public static boolean carriesClientHello(byte[] rawData) {
        byte[] dataToAnalyse = rawData;
        if (isStun(rawData)) {
            dataToAnalyse = carriesStunDataExtension(rawData);
        }

        if (isDtls(dataToAnalyse)) {
            return dataToAnalyse.length > 14 && dataToAnalyse[13] == 0x01;
        } else {
            return false;
        }
    }

    private static byte[] getHandshakeUdpFromClient(HookedConnection connection) {
        if (connection.isInboundTheDtlsClient()) {
            return listToByteArray(connection.getInboundDtlsHandshake().getHistory());
        } else {
            return listToByteArray(connection.getOutboundDtlsHandshake().getHistory());
        }
    }

    private static byte[] getHandshakeUdpFromServer(HookedConnection connection) {
        if (!connection.isInboundTheDtlsClient()) {
            return listToByteArray(connection.getInboundDtlsHandshake().getHistory());
        } else {
            return listToByteArray(connection.getOutboundDtlsHandshake().getHistory());
        }
    }

    private static byte[] listToByteArray(List<byte[]> listOfByteArrays) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        listOfByteArrays.forEach(
                b -> {
                    try {
                        stream.write(b);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        return stream.toByteArray();
    }

    private static <M extends HandshakeMessage> M parseHandshakeMessage(
            byte[] udpPackets, boolean enableTurn, M messageType) {
        WorkflowTrace trace = executeReceiveActions(udpPackets, enableTurn, messageType);
        return (M)
                WorkflowTraceResultUtil.getFirstReceivedMessage(
                        trace,
                        messageType.getHandshakeMessageType(),
                        TLS_ATTACKER_PARSING_CONNECTION_ALIAS);
    }

    private static WorkflowTrace executeReceiveActions(
            byte[] udpPackets, boolean enableTurn, ProtocolMessage... messages) {

        // set up a config with a fake connection
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.DTLS);
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        config.setInitialRecordVersion(ProtocolVersion.DTLS10);
        config.setIndividualTransportPacketsForFragments(true);
        InboundConnection serverConnection =
                new InboundConnection(TLS_ATTACKER_PARSING_CONNECTION_ALIAS, 0, "127.0.0.1");
        serverConnection.setTransportHandlerType(TransportHandlerType.UDP);
        serverConnection.setConnectionTimeout(0);
        serverConnection.setTimeout(0);
        config.setFinishWithCloseNotify(false);
        config.setDefaultServerConnection(serverConnection);
        if (enableTurn) {
            config.setDefaultLayerConfiguration(StackConfiguration.DTLS_OVER_TURN);
        }

        // create and populate workflow trace
        WorkflowTrace trace = new WorkflowTrace(List.of(config.getDefaultServerConnection()));
        Arrays.stream(messages)
                .forEach(
                        m ->
                                trace.addTlsAction(
                                        new ReceiveTillAction(
                                                TLS_ATTACKER_PARSING_CONNECTION_ALIAS, m)));

        State state = new State(config, trace);

        TransportHandler clientTransportHandler =
                new ReadOnlyTransportHandler(
                        ConnectionEndType.CLIENT, new ByteArrayInputStream(udpPackets));

        state.getTlsContext(TLS_ATTACKER_PARSING_CONNECTION_ALIAS)
                .setTransportHandler(clientTransportHandler);
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        state.getConfig().setWorkflowExecutorShouldClose(false);

        new DTLSWorkflowExecutor(state).executeWorkflow();

        LOGGER.trace("Finished execution (executed as planned={})", trace.executedAsPlanned());
        LOGGER.trace("All actions executed: {}", trace.allActionsExecuted());
        LOGGER.trace("Trace:{}", trace);

        return trace;
    }
}
