/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import java.io.File;
import java.net.URL;

public class ProxyConfiguration {

    @Parameter(
            names = {"-timeout", "-t"},
            required = false,
            description = "The timeout for the receiving of messages")
    private long timeout = 1000l; // 5 seconds

    @Parameter(
            names = {"-browser_timeout", "-bt"},
            required = false,
            description = "The timeout for starting a media connection via selenium in seconds")
    private int targetTimeout = 120;

    @Parameter(
            names = {"-rate_limit", "-rl"},
            required = false,
            description = "The maximum connection starts per minute to be performed")
    private float rateLimit = Float.MAX_VALUE;

    @Parameter(
            names = {"-verbose", "-v"},
            required = false,
            description = "Prints additional output")
    private boolean debug = false;

    @Parameter(
            names = {"-very_verbose", "-vv"},
            required = false,
            description = "Prints a lot of additional output")
    private boolean trace = false;

    @Parameter(
            names = {"-help", "--help", "-h", "--usage", "-usage"},
            required = false,
            description = "Shows you how to use this tool :)",
            help = true,
            hidden = true)
    private boolean help = false;

    @Parameter(
            names = {"-targetConfig"},
            required = false,
            description = "Credentials and URLS for the targets that should be analyzed")
    private File targetConfigFile = null;

    @Parameter(
            names = {"-connectionConfig"},
            required = false,
            description =
                    "DTLS connection specifics to filter analysed connections for. Used only for proxied connections.")
    private File connectionConfigFile = null;

    @Parameter(
            names = {"-webDriverUrl"},
            required = false,
            description = "The URL for the remote selenium WebDriver")
    private URL remoteWebDriverUrl = null;

    @Parameter(
            names = {"-local_client_command"},
            required = false,
            description =
                    "If the tool should be executed locally, this is the command that will be executed to start the client.  Should only be used when executing the tool locally")
    private String clientCommand = null;

    @Parameter(
            names = {"-local_server_command"},
            required = false,
            description =
                    "If the tool should be executed locally, this can be used to automatically start the server.  Should only be used when executing the tool locally. Provide the command as a /bin/sh command.")
    private String serverCommand = null;

    @Parameter(
            names = {"-local_server_port"},
            required = false,
            description =
                    "The port the local server is listening on. Should only be used when executing the tool locally")
    private Integer localServerPort = 4433;

    @Parameter(
            names = {"-browserProfileDir", "-pdir"},
            required = false,
            description = "Directory to store browser profiles in for selenium")
    private String browserProfileDir = "~/selenium/browserconfig";

    @Parameter(
            names = {"-headless", "-hl"},
            required = false,
            description = "Whether the browser tests are to be executed in headless (no gui) mode")
    private boolean headless = false;

    @Parameter(
            names = {"-chromeBinaryPath", "-cbp"},
            required = false,
            description =
                    "Location of the Chrome browser binary on the target machine to override default path")
    private String chromeBinaryPath = null;

    @Parameter(
            names = {"-edgeBinaryPath", "-ebp"},
            required = false,
            description =
                    "Location of the Edge browser binary on the target machine to override default path")
    private String edgeBinaryPath = null;

    @Parameter(
            names = {"-firefoxBinaryPath", "-fbp"},
            required = false,
            description =
                    "Location of the Firefox browser binary on the target machine to override default path")
    private String firefoxBinaryPath = null;

    @Parameter(
            names = {"-operaBinaryPath", "-obp"},
            required = false,
            description =
                    "Location of the Opera browser binary on the target machine to override default path")
    private String operaBinaryPath = null;

    @Parameter(
            names = {"-freshMediaServers", "-fms"},
            required = false,
            description =
                    "Will require new connections to differ in media server IP from the previous. Enable this is the service doesn't respond from IPs it previously received a fatal Alert to. Ignored if -hardReset enabled")
    private boolean freshMediaServers = false;

    @Parameter(
            names = {"-noConnectionStack", "-ns"},
            required = false,
            description =
                    "Only hooks the first connection. All other connections will be passed through.")
    private boolean disableConnectionStacking = false;

    @Parameter(
            names = {"-dtls_direction", "-dd"},
            required = false,
            description =
                    "Which side is supposed to send the DTLS client hello. Options are: INBOUND or OUTBOUND. When not set, we automatically test and fix the direction")
    private FilterDirection dtlsFilterDirection = null;

    @Parameter(
            names = {"-internal_interface", "-in"},
            required = true,
            description = "The internal network interface we are listening on for traffic")
    private String internalInterface = null;

    @Parameter(
            names = {"-external_interface", "-out"},
            required = true,
            description = "The external network interface we are listening on for traffic")
    private String externalInterface = null;

    @Parameter(
            names = {"-target_ip", "-ip"},
            required = true,
            description =
                    "The IP address of the target we want to test on our side. E.g. the VM that is running")
    private String targetIp = null;

    @Parameter(
            names = {"-fastReset", "-fr"},
            required = false,
            description =
                    "If supported by the service driver (booter), the analysis will try to maintain a single browser window open and hangup and restart the DTLS connection with functionality from the site.")
    private boolean fastReset = false;

    @Parameter(
            names = {"-recordings", "-rec"},
            required = false,
            description =
                    "A folder in which we store recordings of all the connections we made for debugging and recording purposes")
    private String recordingDirectory = null;

    @Parameter(
            names = {"-dumpMedia", "-dm"},
            required = false,
            description =
                    "Will dump any decrypted DTLS/RTP/RTCP into the recordings directory if encountered. -recordings must be set")
    private boolean dumpMedia = false;

    @Parameter(
            names = {"-skipProviderTest"},
            required = false,
            description =
                    "Will skip the short test that checks the setup functionality in the beginning")
    private boolean skipProviderTest = false;

    @Parameter(
            names = {"-persistBrowserProfile"},
            required = false,
            description =
                    "Will have selenium use the specified browser profile directory to persist settings and cookies.")
    private boolean persistBrowserProfile = false;

    @Parameter(
            names = {"-mediaProcessDuration", "-mpd"},
            required = false,
            description =
                    "The duration in ms that media processing probes will process data for. Increase for services that send media much later than the DTLS handshake, f.e. if a pre call page is present")
    private int mediaProcessDuration = 10000;

    @Parameter(
            names = {"-ex_certs"},
            required = false,
            description =
                    "A (list of) certificate(s) that should be tested with for authentication bypasses.  Requires -ex_key. Separate paths to different .pem certificates with a semicolon")
    private String externalCertificates = null;

    @Parameter(
            names = {"-ex_keys"},
            required = false,
            description =
                    "A key for an external certificate that should be tested with for authentication bypasses. Requires -ex_cert. Separate paths to different .pem keys with a semicolon")
    private String externalKeys = null;

    @Parameter(
            names = {"-maxExecutionRetries", "-exRetry"},
            required = false,
            description =
                    "How often a DTLS connection should be retried in a probe if the endpoint did neither send an alert or send expected messages, i.e. how many retries are sufficient to exclude messages lost in the network")
    private int maxExecutionRetries = 10;

    @Parameter(
            names = {"-maxConnectionRetries", "-cRetry"},
            required = false,
            description =
                    "How often a call should be restarted if no matching connection was found. Consider increasing this value when targeting a rare connection, keep at default if not filtering at all.")
    private int maxConnectionRetries = 15;

    @Parameter(
            names = {"-allowP2P"},
            required = false,
            description = "Allows connections from and to local and multicast addresses")
    private boolean allowP2P = false;

    @Parameter(
            names = {"-disableTlsAttackerLogging"},
            required = false,
            description = "Will disable log messages from the TLS-Attacker framework on all levels")
    private boolean disableTlsAttackerLogging = false;

    @Parameter(
            names = {"-onlyTestRemotePeer"},
            required = false,
            description = "If we only want to test the remote peer")
    private boolean onlyTestRemote = false;

    @Parameter(
            names = {"-onlyTestLocalPeer"},
            required = false,
            description = "If we only want to test the local peer")
    private boolean onlyTestLocal = false;

    @Parameter(
            names = {"-sessionResetPause"},
            required = false,
            description =
                    "Milliseconds to wait for the user to end a session before analyzing the next connection. Setting this to 0 will wait for user input to resume with next the session. A reset pause will only appear when applications are detected to use multiple connections per session.")
    private int sessionResetPause = 0;

    public ProxyConfiguration() {}

    public boolean isOnlyTestRemote() {
        return onlyTestRemote;
    }

    public void setOnlyTestRemote(boolean onlyTestRemote) {
        this.onlyTestRemote = onlyTestRemote;
    }

    public boolean isOnlyTestLocal() {
        return onlyTestLocal;
    }

    public void setOnlyTestLocal(boolean onlyTestLocal) {
        this.onlyTestLocal = onlyTestLocal;
    }

    public boolean isAllowP2P() {
        return allowP2P;
    }

    public void setAllowP2P(boolean allowP2P) {
        this.allowP2P = allowP2P;
    }

    public String[] getExternalCertificates() {
        if (externalCertificates == null) {
            return new String[0];
        }
        return externalCertificates.split(";");
    }

    public void setExternalCertificates(String externalCertificates) {
        this.externalCertificates = externalCertificates;
    }

    public String[] getExternalKeys() {
        if (externalKeys == null) {
            return new String[0];
        }
        return externalKeys.split(";");
    }

    public void setExternalKeys(String externalKeys) {
        this.externalKeys = externalKeys;
    }

    public String getRecordingDirectory() {
        return recordingDirectory;
    }

    public void setRecordingDirectory(String recordingDirectory) {
        this.recordingDirectory = recordingDirectory;
    }

    public FilterDirection getDtlsFilterDirection() {
        return dtlsFilterDirection;
    }

    public void setDtlsFilterDirection(FilterDirection dtlsFilterDirection) {
        this.dtlsFilterDirection = dtlsFilterDirection;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setExternalInterface(String externalInterface) {
        this.externalInterface = externalInterface;
    }

    public String getExternalInterface() {
        return externalInterface;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public String getInternalInterface() {
        return internalInterface;
    }

    public void setInternalInterface(String networkInterface) {
        this.internalInterface = networkInterface;
    }

    public URL getRemoteWebDriverUrl() {
        return remoteWebDriverUrl;
    }

    public void setRemoteWebDriverUrl(URL remoteWebDriverUrl) {
        this.remoteWebDriverUrl = remoteWebDriverUrl;
    }

    public File getTargetConfigFile() {
        return targetConfigFile;
    }

    public void setTargetConfigFile(File targetConfigFile) {
        this.targetConfigFile = targetConfigFile;
    }

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    public float getRateLimit() {
        return rateLimit;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public boolean isTrace() {
        return trace;
    }

    public void setTrace(boolean trace) {
        this.trace = trace;
    }

    public boolean isHelp() {
        return help;
    }

    public void setHelp(boolean help) {
        this.help = help;
    }

    public int getTargetTimeout() {
        return targetTimeout;
    }

    public void setTargetTimeout(int targetTimeout) {
        this.targetTimeout = targetTimeout;
    }

    public String getClientCommand() {
        return clientCommand;
    }

    public void setClientCommand(String clientCommand) {
        this.clientCommand = clientCommand;
    }

    public Integer getLocalServerPort() {
        return localServerPort;
    }

    public void setLocalServerPort(int localServerPort) {
        this.localServerPort = localServerPort;
    }

    public String getServerCommand() {
        return serverCommand;
    }

    public void setServerCommand(String serverCommand) {
        this.serverCommand = serverCommand;
    }

    public boolean isHeadless() {
        return headless;
    }

    public void setHeadless(boolean headless) {
        this.headless = headless;
    }

    public String getBrowserProfileDir() {
        return browserProfileDir;
    }

    public void setBrowserProfileDir(String browserProfileDir) {
        this.browserProfileDir = browserProfileDir;
    }

    public String getChromeBinaryPath() {
        return chromeBinaryPath;
    }

    public void setChromeBinaryPath(String chromeBinaryPath) {
        this.chromeBinaryPath = chromeBinaryPath;
    }

    public String getEdgeBinaryPath() {
        return edgeBinaryPath;
    }

    public void setEdgeBinaryPath(String edgeBinaryPath) {
        this.edgeBinaryPath = edgeBinaryPath;
    }

    public String getFirefoxBinaryPath() {
        return firefoxBinaryPath;
    }

    public void setFirefoxBinaryPath(String firefoxBinaryPath) {
        this.firefoxBinaryPath = firefoxBinaryPath;
    }

    public String getOperaBinaryPath() {
        return operaBinaryPath;
    }

    public void setOperaBinaryPath(String operaBinaryPath) {
        this.operaBinaryPath = operaBinaryPath;
    }

    public boolean isFreshMediaServers() {
        return freshMediaServers;
    }

    public int getMediaProcessDuration() {
        return mediaProcessDuration;
    }

    public void setMediaProcessDuration(int mediaProcessDuration) {
        this.mediaProcessDuration = mediaProcessDuration;
    }

    public boolean isSkipProviderTest() {
        return skipProviderTest;
    }

    public void setSkipProviderTest(boolean skipProviderTest) {
        this.skipProviderTest = skipProviderTest;
    }

    public boolean isFastReset() {
        return fastReset;
    }

    public void setFastReset(boolean fastReset) {
        this.fastReset = fastReset;
    }

    public boolean isDisableConnectionStacking() {
        return this.disableConnectionStacking;
    }

    public boolean isPersistBrowserProfile() {
        return persistBrowserProfile;
    }

    public void setPersistBrowserProfile(boolean persistBrowserProfile) {
        this.persistBrowserProfile = persistBrowserProfile;
    }

    public boolean isDumpMedia() {
        return dumpMedia;
    }

    public void setDumpMedia(boolean dumpMedia) {
        this.dumpMedia = dumpMedia;
    }

    public int getMaxExecutionRetries() {
        return maxExecutionRetries;
    }

    public void setMaxExecutionRetries(int maxExecutionRetries) {
        this.maxExecutionRetries = maxExecutionRetries;
    }

    public boolean isDisableTlsAttackerLogging() {
        return disableTlsAttackerLogging;
    }

    public void setDisableTlsAttackerLogging(boolean disableTlsAttackerLogging) {
        this.disableTlsAttackerLogging = disableTlsAttackerLogging;
    }

    public File getConnectionConfigFile() {
        return connectionConfigFile;
    }

    public void setConnectionConfigFile(File connectionConfigFile) {
        this.connectionConfigFile = connectionConfigFile;
    }

    public int getMaxConnectionRetries() {
        return maxConnectionRetries;
    }

    public int getSessionResetPause() {
        return sessionResetPause;
    }

    public void setSessionResetPause(int sessionResetPause) {
        this.sessionResetPause = sessionResetPause;
    }
}
