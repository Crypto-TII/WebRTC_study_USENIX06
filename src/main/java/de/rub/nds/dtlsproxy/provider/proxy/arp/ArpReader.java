/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy.arp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ArpReader {

    private static final Logger LOGGER = LogManager.getLogger();

    public ArpReader() {}

    public List<ArpEntry> readArpCache() {
        try {
            LOGGER.debug("Reading ARP cache");
            Process process = Runtime.getRuntime().exec("arp -an");
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            List<ArpEntry> arpEntries = new LinkedList<>();
            Pattern pattern = Pattern.compile("\\((.*?)\\) at (.*?) ");
            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    String ipAddress = matcher.group(1);
                    String macAddress = matcher.group(2);
                    LOGGER.debug("IP: {} MAC: {}", ipAddress, macAddress);
                    arpEntries.add(new ArpEntry(ipAddress, macAddress));
                }
            }
            return arpEntries;
        } catch (IOException e) {
            throw new RuntimeException("Could not read ARP cache");
        }
    }
}
