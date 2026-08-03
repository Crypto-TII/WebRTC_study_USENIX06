/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.packet;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

public final class PacketCaptureController {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final HashMap<String, Set<PacketCapturer>> liveCapturers = new HashMap<>();

    private static PcapHandle dumpHandle = null;

    private PacketCaptureController() {}

    public static synchronized void capturePacket(Packet packet) {

        // forward packet to all active capturers
        for (Set<PacketCapturer> capturerSet : liveCapturers.values()) {
            for (PacketCapturer capturer : capturerSet) {
                capturer.capture(packet);
            }
        }
    }

    public static synchronized void startCapture(String path, String title) {

        if (dumpHandle == null) {
            throw new RuntimeException("Failed to start capture, no pcap handle was registered");
        }

        LOGGER.debug("Registering capturing for {}", title);

        PcapDumper dumper = null;

        final File writeOutFile = new File(path + "/" + title + ".pcap");
        try {
            dumper = dumpHandle.dumpOpen(writeOutFile.getAbsolutePath());
        } catch (PcapNativeException | NotOpenException e) {
            LOGGER.error(
                    "Failed to register packet capturing of {}: Error opening Dumper", title, e);
            return;
        }

        if (!liveCapturers.containsKey(title)) {
            liveCapturers.put(title, new HashSet<>());
        }

        liveCapturers.get(title).add(new PacketCapturer(dumper));
    }

    public static synchronized void stopCapture(String title) {

        if (!liveCapturers.containsKey(title)) {
            throw new RuntimeException(
                    "Could not stop packet capture: Capture with the given title not found: "
                            + title);
        }

        LOGGER.debug("Stopping capture for {}", title);

        for (PacketCapturer capturer : liveCapturers.get(title)) {
            capturer.close();
        }

        liveCapturers.remove(title);
    }

    public static synchronized void setDumpHandle(PcapHandle dumpHandle) {
        PacketCaptureController.dumpHandle = dumpHandle;
    }

    public static synchronized void closeAll() {
        for (String key : liveCapturers.keySet()) {
            stopCapture(key);
        }
    }
}
