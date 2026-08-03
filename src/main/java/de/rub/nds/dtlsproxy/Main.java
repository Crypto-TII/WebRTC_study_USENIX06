/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy;

import com.beust.jcommander.JCommander;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.LocalConnectionProvider;
import de.rub.nds.dtlsproxy.report.WebRtcFullReport;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.X509Util;
import jakarta.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.filter.ThresholdFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    private static long startTime;

    public static void main(String[] args) throws IOException, JAXBException {
        startTime = System.currentTimeMillis();
        LOGGER.debug("Adding BouncyCastleProvider");
        Security.addProvider(new BouncyCastleProvider());

        ProxyConfiguration configuration = new ProxyConfiguration();
        JCommander commander = JCommander.newBuilder().addObject(configuration).build();
        try {
            commander.parse(args);
        } catch (Exception E) {
            LOGGER.error(E);
            commander.usage();
            return;
        }
        if (configuration.isHelp()) {
            commander.usage();
            return;
        }
        if (configuration.isOnlyTestLocal() && configuration.isOnlyTestRemote()) {
            LOGGER.error("Only one of the flags --onlyTestLocal and --onlyTestRemote can be set");
            return;
        }
        setLoggingLevels(configuration);

        LOGGER.trace("Running with arguments: {}", String.join(" ", args));

        // init trusted certificate cache to avoid init at probing time
        X509Util.initCache(configuration);

        if (configuration.getRecordingDirectory() != null) {
            File f = new File(configuration.getRecordingDirectory());
            if (!f.exists()) {
                f.mkdirs();
            }
        }

        if (configuration.getClientCommand() != null) {
            testIndividualLocalConfiguration(configuration);
        } else {
            if (configuration.getTargetConfigFile() == null
                    || !configuration.getTargetConfigFile().exists()) {
                LOGGER.error("Target file does not exist");
                return;
            }
            testGlobalConfiguration(configuration);
        }

        // Create runtime log output
        final long endTime = System.currentTimeMillis();
        final long runtimeHours = TimeUnit.MILLISECONDS.toHours(endTime - startTime);
        final long runtimeMinutes = TimeUnit.MILLISECONDS.toMinutes(endTime - startTime) % 60;
        final long runtimeSeconds = TimeUnit.MILLISECONDS.toSeconds(endTime - startTime) % 60;

        LOGGER.info(
                "Profiling concluded after {}",
                String.format(
                        "%02dhrs %02dmin %02ds", runtimeHours, runtimeMinutes, runtimeSeconds));
    }

    private static void testGlobalConfiguration(ProxyConfiguration configuration)
            throws IOException {
        GlobalTester tester = new GlobalTester(configuration);
        LOGGER.info("Testing all configurations...");
        try {
            WebRtcFullReport report = tester.testAllConfigurations();
            LOGGER.info(report.getReport());
        } finally {
            LOGGER.info("Shutting down...");
            tester.shutdown();
        }
    }

    private static void testIndividualLocalConfiguration(ProxyConfiguration configuration) {
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        configuration,
                        new WebRtcPlatformReport(
                                configuration.getClientCommand(), FilterDirection.INBOUND),
                        new LocalConnectionProvider(configuration),
                        null);
        IndividualTester tester = new IndividualTester(webrtcExecutionContext);
        WebRtcPlatformReport report = tester.performTest();
        LOGGER.info("\n" + report.toString());
    }

    private static void setLoggingLevels(ProxyConfiguration configuration) {
        // Get LoggerContext to directly configure the log4j2 system
        final LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        final org.apache.logging.log4j.core.config.Configuration config = ctx.getConfiguration();

        // Determine console log level based on configuration flags
        Level consoleLevel = Level.INFO; // Default level
        if (configuration.isTrace()) {
            consoleLevel = Level.TRACE;
        } else if (configuration.isDebug()) {
            consoleLevel = Level.DEBUG;
        }

        // Set console level by configuring its ThresholdFilter
        ConsoleAppender consoleAppender = config.getAppender("Console");
        if (consoleAppender != null) {
            LOGGER.info("Setting console log level to {}", consoleLevel);

            // Remove existing filters from console appender
            consoleAppender.stop();
            if (consoleAppender.hasFilter()) {
                consoleAppender.removeFilter(consoleAppender.getFilter());
            }
            // Add threshold filter with desired level
            ThresholdFilter thresholdFilter =
                    ThresholdFilter.createFilter(
                            consoleLevel,
                            org.apache.logging.log4j.core.Filter.Result.ACCEPT,
                            org.apache.logging.log4j.core.Filter.Result.DENY);
            consoleAppender.addFilter(thresholdFilter);
            consoleAppender.start();
        }

        // Set package-specific levels
        if (configuration.isDisableTlsAttackerLogging()) {
            Configurator.setLevel("de.rub.nds.asn1", Level.OFF);
            Configurator.setLevel("de.rub.nds.x509", Level.OFF);
            Configurator.setLevel("de.rub.nds.modifiablevariable", Level.OFF);
            Configurator.setLevel("de.rub.nds.tlsattacker", Level.OFF);
            Configurator.setLevel("de.rub.nds.tlsattacker.core.ice.parser", Level.OFF);
            Configurator.setLevel("de.rub.nds.dtlsproxy", Level.TRACE);
        } else {
            Configurator.setLevel("de.rub.nds.asn1", Level.INFO);
            Configurator.setLevel("de.rub.nds.x509", Level.DEBUG);
            Configurator.setLevel("de.rub.nds.tlsattacker", Level.DEBUG);
            Configurator.setLevel("de.rub.nds.dtlsproxy", Level.TRACE);
            Configurator.setLevel("de.rub.nds.tlsattacker.core.ice.parser", Level.WARN);
            Configurator.setLevel(
                    "de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher", Level.ERROR);
        }

        // Ensure Selenium logs are set to WARN level
        Configurator.setLevel("org.openqa.selenium", Level.WARN);

        // Update the configuration
        ctx.updateLoggers();
    }
}
