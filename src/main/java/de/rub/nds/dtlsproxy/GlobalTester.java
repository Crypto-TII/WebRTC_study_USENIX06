/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy;

import de.rub.nds.dtlsproxy.booter.CapabilitiesFactory;
import de.rub.nds.dtlsproxy.config.*;
import de.rub.nds.dtlsproxy.enums.Browser;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.TargetName;
import de.rub.nds.dtlsproxy.packet.PacketCaptureController;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.ConnectionProvider;
import de.rub.nds.dtlsproxy.provider.ProxiedConnectionProvider;
import de.rub.nds.dtlsproxy.provider.proxy.PacketFilter;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.provider.proxy.arp.ArpEntry;
import de.rub.nds.dtlsproxy.provider.proxy.arp.ArpReader;
import de.rub.nds.dtlsproxy.report.WebRtcFullReport;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.SessionNotCreatedException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;

public class GlobalTester {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProxyConfiguration proxyConfiguration;

    private ConfigList configList;
    private ConnectionConfig connectionConfig;

    private final PacketFilter inboundUdpFilter;
    private final PacketFilter outboundUdpFilter;
    private final SessionManager sessionManager;

    public GlobalTester(ProxyConfiguration proxyConfiguration) throws IOException {
        this.proxyConfiguration = proxyConfiguration;

        String internalInterfaceName = proxyConfiguration.getInternalInterface();
        String externalInterfaceName = proxyConfiguration.getExternalInterface();

        try {
            if (proxyConfiguration.getConnectionConfigFile() == null) {
                LOGGER.debug("No connection configuration found. Not filtering DTLS connections.");
                this.connectionConfig = new ConnectionConfig();
            } else {
                this.connectionConfig =
                        ConfigParser.read(
                                proxyConfiguration.getConnectionConfigFile(),
                                ConnectionConfig.class);
                if (!this.connectionConfig.isValid()) {
                    throw new RemoteException("Connection config contains errors");
                }
            }
            LOGGER.debug("Connection filter settings:\n{}", this.connectionConfig);

            this.sessionManager = new SessionManager(connectionConfig);

            PcapNetworkInterface inboundInterface = Pcaps.getDevByName(internalInterfaceName);
            PcapNetworkInterface outboundInterface = Pcaps.getDevByName(externalInterfaceName);

            ArpReader reader = new ArpReader();
            List<ArpEntry> arpEntries = reader.readArpCache();

            Inet4Address inboundInterfaceSourceIp = getIpV4Address(inboundInterface);
            MacAddress inboundInterfaceSourceMac = getMacForInterface(inboundInterface);
            Inet4Address outboundInterfaceSourceIp = getIpV4Address(outboundInterface);
            MacAddress outboundInterfaceSourceMac = getMacForInterface(outboundInterface);
            Inet4Address inboundTargetIp =
                    (Inet4Address) InetAddress.getByName(proxyConfiguration.getTargetIp());
            MacAddress inboundForwardToMac =
                    getMacForIp(arpEntries, proxyConfiguration.getTargetIp());
            MacAddress outboundGatewayMac = getMacForIp(arpEntries, getDefaultRouteGateway());

            inboundUdpFilter =
                    new PacketFilter(
                            proxyConfiguration,
                            FilterDirection.INBOUND,
                            sessionManager,
                            internalInterfaceName,
                            externalInterfaceName,
                            inboundInterfaceSourceIp,
                            inboundInterfaceSourceMac,
                            outboundInterfaceSourceIp,
                            outboundInterfaceSourceMac,
                            inboundTargetIp,
                            inboundForwardToMac,
                            outboundGatewayMac);
            outboundUdpFilter =
                    new PacketFilter(
                            proxyConfiguration,
                            FilterDirection.OUTBOUND,
                            sessionManager,
                            externalInterfaceName,
                            internalInterfaceName,
                            outboundInterfaceSourceIp,
                            outboundInterfaceSourceMac,
                            inboundInterfaceSourceIp,
                            inboundInterfaceSourceMac,
                            inboundTargetIp,
                            inboundForwardToMac,
                            outboundGatewayMac);
            inboundUdpFilter.startThread("InboundFilter");
            outboundUdpFilter.startThread("OutboundFilter");
            this.configList =
                    ConfigParser.read(proxyConfiguration.getTargetConfigFile(), ConfigList.class);
            LOGGER.debug("Target configurations found:");
            for (TargetConfig targetConfig : configList.getTargetConfigList()) {
                LOGGER.debug(targetConfig);
            }
        } catch (Exception ex) {
            LOGGER.warn(ex);
            throw new RuntimeException("Could not initialize Tester", ex);
        }
    }

    private MacAddress getMacForInterface(PcapNetworkInterface pcapNetworkInterface) {
        if (pcapNetworkInterface.getLinkLayerAddresses().isEmpty()) {
            throw new RuntimeException(
                    "Could not determine mac address for interface: "
                            + pcapNetworkInterface.getName());
        }
        return MacAddress.getByAddress(
                pcapNetworkInterface.getLinkLayerAddresses().get(0).getAddress());
    }

    private Inet4Address getIpV4Address(PcapNetworkInterface inboundInterface) {
        for (PcapAddress address : inboundInterface.getAddresses()) {
            if (address.getAddress() instanceof Inet4Address) {
                return (Inet4Address) address.getAddress();
            }
        }
        throw new RuntimeException(
                "Could not determine ip address for interface: " + inboundInterface.getName());
    }

    private MacAddress getMacForIp(List<ArpEntry> arpEntries, String defaultRouteGateway) {
        for (ArpEntry entry : arpEntries) {
            if (entry.getIpAddress().equals(defaultRouteGateway)) {
                LOGGER.debug(entry.getMacAddress()); // TODO This can fail with <incomplete>
                return MacAddress.getByName(entry.getMacAddress());
            }
        }
        throw new RuntimeException(
                "Could not determine mac address for ip: " + defaultRouteGateway);
    }

    protected String getDefaultRouteGateway() throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("netstat -rn");

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;

        while ((line = reader.readLine()) != null) {
            if (line.startsWith("0.0.0.0")) {
                String[] parts = line.split("\\s+");
                return parts[1];
            }
        }
        reader.close();
        process.waitFor();
        return null;
    }

    public WebRtcFullReport testAllConfigurations() throws IOException {

        WebRtcFullReport fullReport = new WebRtcFullReport();
        for (Browser browser : Browser.values()) {
            LOGGER.debug("Testing browser {}", browser.name());
            for (TargetName name : TargetName.values()) {
                LOGGER.debug("Testing target {}", name.name());
                TargetConfig targetConfig = configList.get(name);
                if (targetConfig == null) {
                    LOGGER.debug("Do not have credentials for {}, skipping", name.name());
                    continue;
                }
                if (targetConfig.getBrowsers() == null) {
                    LOGGER.debug("No browsers specified for {}, skipping", name.name());
                    continue;
                }
                if (!Arrays.asList(targetConfig.getBrowsers()).contains(browser)) {
                    LOGGER.debug(
                            "No test requested for {} on {}, skipping",
                            name.name(),
                            browser.name());
                    continue;
                }
                LOGGER.trace(
                        "Attempting to summon selenium for {} on {}", name.name(), browser.name());
                Capabilities capabilities;
                try {
                    capabilities =
                            CapabilitiesFactory.createCapabilities(
                                    browser, proxyConfiguration, targetConfig);
                } catch (UnsupportedOperationException E) {
                    LOGGER.warn("Cannot test browser: " + browser.name(), E);
                    continue;
                }
                ConnectionProvider connectionProvider;
                try {
                    connectionProvider =
                            createConnectionProvider(targetConfig, capabilities, browser);
                } catch (SessionNotCreatedException e) {
                    LOGGER.warn("Failed to create connection provider for {}", browser.name(), e);
                    continue;
                }
                WebRtcPlatformReport platformReport =
                        new WebRtcPlatformReport(
                                name.name()
                                        + "-"
                                        + capabilities.getBrowserName()
                                        + "-"
                                        + capabilities.getBrowserVersion()
                                        + "-"
                                        + capabilities.getPlatformName(),
                                proxyConfiguration.getDtlsFilterDirection());
                if (proxyConfiguration.getDtlsFilterDirection() != null) {
                    connectionProvider.lockInFilterDirection(
                            proxyConfiguration.getDtlsFilterDirection());
                }
                WebrtcExecutionContext webrtcExecutionContext =
                        new WebrtcExecutionContext(
                                proxyConfiguration,
                                platformReport,
                                connectionProvider,
                                sessionManager);

                IndividualTester tester = new IndividualTester(webrtcExecutionContext);

                platformReport = tester.performTest();
                fullReport.addReport(platformReport);
                LOGGER.info(
                        "Finished tests for target {} on {} after {} DTLS connections",
                        name.name(),
                        browser.name(),
                        connectionProvider.getConnectionCounter());
                connectionProvider.closeProvider();
            }
        }
        return fullReport;
    }

    private ConnectionProvider createConnectionProvider(
            TargetConfig targetConfig, Capabilities capabilities, Browser browser) {
        return new ProxiedConnectionProvider(
                targetConfig, capabilities, proxyConfiguration, browser, sessionManager);
    }

    public void shutdown() {
        LOGGER.debug("Shutting down filters");
        inboundUdpFilter.shutdown();
        outboundUdpFilter.shutdown();
        PacketCaptureController.closeAll();
    }
}
