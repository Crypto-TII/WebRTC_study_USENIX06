/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.config.TargetConfig;
import de.rub.nds.dtlsproxy.enums.Browser;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.time.Duration;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.UnexpectedAlertBehaviour;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.AbstractDriverOptions;
import org.openqa.selenium.remote.CapabilityType;

public class CapabilitiesFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private CapabilitiesFactory() {}

    public static Capabilities createCapabilities(
            Browser browser, ProxyConfiguration proxyConfiguration, TargetConfig targetConfig) {

        switch (browser) {
            case CHROME:
                return getChromeCapabilities(proxyConfiguration, targetConfig);
            case FIREFOX:
                return getFirefoxCapabilities(proxyConfiguration, targetConfig);
            case EDGE:
                return getEdgeCapabilities(proxyConfiguration, targetConfig);
            case OPERA:
                try {
                    return getOperaCapabilities(
                            proxyConfiguration, targetConfig); // fall if not implemented
                } catch (Exception e) {
                    throw new UnsupportedOperationException(
                            "Could not create booter. Selenium version does not support Opera. Use selenium <= 4.4.0");
                }
            default:
                throw new UnsupportedOperationException("Could not create booter. Not supported");
        }
    }

    private static Capabilities getFirefoxCapabilities(
            ProxyConfiguration proxyConfiguration, TargetConfig targetConfig) {

        FirefoxOptions firefoxOptions = new FirefoxOptions();
        firefoxOptions.setPlatformName("linux");
        // disable quic
        firefoxOptions.addPreference("network.http.http3.enable", false);
        // handle microphone pop-ups
        firefoxOptions.addPreference("media.navigator.enabled", true);
        firefoxOptions.addPreference("media.navigator.permission.disabled", true);
        firefoxOptions.addPreference("media.navigator.streams.fake", true);
        firefoxOptions.setPageLoadTimeout(Duration.ofMinutes(2));

        // open without GUI if specified by user
        if (proxyConfiguration.isHeadless()) {
            firefoxOptions.addArguments("-headless");
        }

        // if binary specified, set to prefer path over default locating
        if (proxyConfiguration.getFirefoxBinaryPath() != null) {
            firefoxOptions.setBinary(proxyConfiguration.getFirefoxBinaryPath());
        }

        // set profile to persist mic and xdg settings
        if (proxyConfiguration.isPersistBrowserProfile()) {
            firefoxOptions.addArguments(
                    "--profile-root="
                            + proxyConfiguration.getBrowserProfileDir()
                            + File.separator
                            + "firefox");
        }

        firefoxOptions.setCapability(
                CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR, UnexpectedAlertBehaviour.ACCEPT);

        return firefoxOptions;
    }

    private static Capabilities getChromeCapabilities(
            ProxyConfiguration proxyConfiguration, TargetConfig targetConfig) {

        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.setPlatformName("linux");
        chromeOptions.setPageLoadTimeout(Duration.ofMinutes(2));
        chromeOptions.addArguments(
                Arrays.asList(
                        "--disable-quic",
                        "--disable-infobars",
                        "--use-fake-ui-for-media-stream",
                        "--ignore-certificate-errors",
                        "--unsafely-treat-insecure-origin-as-secure=" + targetConfig.getUrl()));

        // set profile to persist mic and xdg settings
        if (proxyConfiguration.isPersistBrowserProfile()) {
            LOGGER.trace(
                    "Setting browser profile directory to {}",
                    proxyConfiguration.getBrowserProfileDir() + File.separator + "chrome");
            chromeOptions.addArguments(
                    "--user-data-dir="
                            + proxyConfiguration.getBrowserProfileDir()
                            + File.separator
                            + "chrome");
        }

        // open without GUI if specified by user
        if (proxyConfiguration.isHeadless()) {
            chromeOptions.addArguments("headless");
        }

        // if binary specified, set to prefer path over default locating
        if (proxyConfiguration.getChromeBinaryPath() != null) {
            chromeOptions.setBinary(proxyConfiguration.getChromeBinaryPath());
        }

        // try to trick automation detection
        chromeOptions.addArguments(
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox");
        chromeOptions.addArguments("window-size=1920,1080");
        chromeOptions.setExperimentalOption(
                "excludeSwitches", Collections.singletonList("enable-automation"));
        chromeOptions.setExperimentalOption("useAutomationExtension", null);

        chromeOptions.setCapability(
                CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR, UnexpectedAlertBehaviour.ACCEPT);

        return chromeOptions;
    }

    private static Capabilities getEdgeCapabilities(
            ProxyConfiguration proxyConfiguration, TargetConfig targetConfig) {

        EdgeOptions edgeOptions = new EdgeOptions();
        edgeOptions.setPlatformName("linux");
        edgeOptions.setPageLoadTimeout(Duration.ofMinutes(2));
        edgeOptions.setBinary("/opt/microsoft/msedge/msedge");
        edgeOptions.addArguments(
                Arrays.asList(
                        "--disable-quic",
                        "--disable-infobars",
                        "--use-fake-ui-for-media-stream",
                        "--unsafely-treat-insecure-origin-as-secure=" + targetConfig.getUrl()));

        edgeOptions.setExperimentalOption(
                "excludeSwitches", Arrays.asList("disable-popup-blocking"));

        Map<String, Object> prefs = new HashMap<>();
        Map<String, Object> profile = new HashMap<>();
        Map<String, Object> contentSettings = new HashMap<>();

        // 0 - Default, 1 - Allow, 2 - Block
        contentSettings.put("notifications", 1);
        profile.put("managed_default_content_settings", contentSettings);
        prefs.put("profile", profile);
        edgeOptions.setExperimentalOption("prefs", prefs);

        // set profile to persist mic and xdg settings
        if (proxyConfiguration.isPersistBrowserProfile()) {
            edgeOptions.addArguments(
                    "--user-data-dir="
                            + proxyConfiguration.getBrowserProfileDir()
                            + File.separator
                            + "edge");
        }

        // open without GUI if specified by user
        if (proxyConfiguration.isHeadless()) {
            edgeOptions.addArguments("headless");
        }

        // if binary specified, set to prefer path over default locating
        if (proxyConfiguration.getEdgeBinaryPath() != null) {
            edgeOptions.setBinary(proxyConfiguration.getEdgeBinaryPath());
        }

        // try to trick automation detection
        edgeOptions.addArguments(
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox");
        edgeOptions.addArguments("window-size=1920,1080");
        edgeOptions.setExperimentalOption(
                "excludeSwitches", Collections.singletonList("enable-automation"));
        edgeOptions.setExperimentalOption("useAutomationExtension", null);

        edgeOptions.setCapability(
                CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR, UnexpectedAlertBehaviour.ACCEPT);

        return edgeOptions;
    }

    private static Capabilities getOperaCapabilities(
            ProxyConfiguration proxyConfiguration, TargetConfig targetConfig)
            throws InvocationTargetException,
                    InstantiationException,
                    IllegalAccessException,
                    ClassNotFoundException,
                    NoSuchMethodException {

        Class<?> operaOptionsClass = Class.forName("org.openqa.selenium.opera.OperaOptions");

        AbstractDriverOptions operaOptions =
                (AbstractDriverOptions) operaOptionsClass.getConstructors()[0].newInstance();
        operaOptions.setPlatformName("linux");
        operaOptions.setPageLoadTimeout(Duration.ofMinutes(2));

        // open without GUI if specified by user
        if (proxyConfiguration.isHeadless()) {
            operaOptionsClass
                    .getMethod("addArguments", List.class)
                    .invoke(operaOptions, Arrays.asList("headless"));
        }

        Map<String, Object> prefs = new HashMap<>();
        Map<String, Object> profile = new HashMap<>();
        Map<String, Object> contentSettings = new HashMap<>();

        // SET CHROME OPTIONS
        // 0 - Default, 1 - Allow, 2 - Block
        contentSettings.put("notifications", 1);
        profile.put("managed_default_content_settings", contentSettings);
        prefs.put("profile", profile);
        operaOptionsClass
                .getMethod("setExperimentalOption", String.class, Object.class)
                .invoke(operaOptions, "prefs", prefs);

        // if binary specified, set to prefer path over default locating
        if (proxyConfiguration.getOperaBinaryPath() != null) {
            operaOptionsClass
                    .getMethod("setBinary")
                    .invoke(proxyConfiguration.getOperaBinaryPath());
        }

        String argDisableQuic = "--disable-quic";
        String argDisableInfoBars = "--disable-infobars";
        String argFakeMedia = "--use-fake-ui-for-media-stream";
        String argAllowUnsecureOrigin =
                "--unsafely-treat-insecure-origin-as-secure=" + targetConfig.getUrl();

        // try to trick automation detection
        String argDisableAutomation = "--disable-blink-features=AutomationControlled";
        String argDisableDevShmUsage = "--disable-dev-shm-usage";
        String argNoSandbox = "--no-sandbox";
        String argProfile = "";
        // set profile to persist mic and xdg settings
        if (proxyConfiguration.isPersistBrowserProfile()) {
            argProfile =
                    "--user-data-dir="
                            + proxyConfiguration.getBrowserProfileDir()
                            + File.separator
                            + "opera";
        }

        List<String> args =
                Arrays.asList(
                        argDisableQuic,
                        argDisableInfoBars,
                        argFakeMedia,
                        argAllowUnsecureOrigin,
                        argDisableAutomation,
                        argDisableDevShmUsage,
                        argNoSandbox,
                        argProfile);
        operaOptionsClass.getMethod("addArguments", List.class).invoke(operaOptions, args);

        operaOptionsClass
                .getMethod("setExperimentalOption", String.class, Object.class)
                .invoke(
                        operaOptions,
                        "excludeSwitches",
                        Collections.singletonList("enable-automation"));

        operaOptions.setCapability(
                CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR, UnexpectedAlertBehaviour.ACCEPT);

        return operaOptions;
    }
}
