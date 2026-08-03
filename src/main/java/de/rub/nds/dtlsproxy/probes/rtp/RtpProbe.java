/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.Probe;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass.AuthBypass;
import de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass.AuthBypassFactory;
import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtpHandler;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtpNullHandler;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RtpProbe extends Probe {

    static final Logger LOGGER = LogManager.getLogger();

    private final boolean requiresClientAuthBypass;
    private final boolean requiresServerAuthBypass;
    private final MediaReport mediaReport;

    private AuthBypass authBypass = null;
    private WorkflowTrace authBypassTrace;

    private RtpCrypto clientToAttackerRtpCrypto;
    private RtpCrypto attackerToServerRtpCrypto;

    private TlsContext clientToAttackerTlsContext;
    private TlsContext attackerToServerTlsContext;

    protected boolean enableSrtp = true;

    private boolean suppressErrorMessages = false;

    protected RtpProbe(
            WebrtcExecutionContext webrtcExecutionContext,
            String strategyLabel,
            boolean requiresClientAuthBypass,
            boolean requiresServerAuthBypass) {
        super(webrtcExecutionContext);
        this.mediaReport = new MediaReport(strategyLabel);
        this.requiresClientAuthBypass = requiresClientAuthBypass;
        this.requiresServerAuthBypass = requiresServerAuthBypass;
    }

    public TraceableConnection mitm(WebRtcPlatformReport report) throws IOException {

        Config config = authBypass.createConfig(getProxyConfiguration(), report);

        TraceableConnection connection =
                createConnection(
                        config,
                        authBypassTrace,
                        authBypass.getClientToAttackerConnectionAlias(),
                        authBypass.getAttackerToServerConnectionAlias());

        LOGGER.info("Executing MitM trace");
        WorkflowExecutor executor = new DTLSWorkflowExecutor(connection.getState());
        executor.executeWorkflow();

        LOGGER.debug(
                "Finished execution (executed as planned={})",
                connection.getState().getWorkflowTrace().executedAsPlanned());

        LOGGER.debug(
                "All actions executed: {}",
                connection.getState().getWorkflowTrace().allActionsExecuted());
        LOGGER.debug("Trace:{}", connection.getState().getWorkflowTrace());

        if (!authBypassTrace.allActionsExecuted() || !authBypassTrace.executedAsPlanned()) {
            LOGGER.info("MitM Failed");
            mediaReport.setDtlsHandshakeSuccess(false);
            throw new RuntimeException("DTLS MitM failed");
        }
        getPostAnalyzer().consume(connection.getState(), connection.getConnectionInterface());
        clientToAttackerTlsContext =
                connection
                        .getState()
                        .getTlsContext(authBypass.getClientToAttackerConnectionAlias());
        attackerToServerTlsContext =
                connection
                        .getState()
                        .getTlsContext(authBypass.getAttackerToServerConnectionAlias());

        return connection;
    }

    void initSrtp() {
        try {
            LOGGER.trace("Setting up RTP crypto: clientToAttacker, acting as server");
            clientToAttackerRtpCrypto = createRtpCrypto(getClientToAttackerTlsContext(), true);
            LOGGER.trace("Setting up RTP crypto: attackerToServer, acting as client");
            attackerToServerRtpCrypto = createRtpCrypto(getAttackerToServerTlsContext(), false);
        } catch (Exception e) {
            throw new RuntimeException("Srtp setup failed: ", e);
        }
    }

    @Override
    public void runChecks(WebRtcPlatformReport report) {
        try {

            // assign bypass to this probe
            selectAuthBypass(report);

            if (getAuthBypass() == null) {
                // no bypass matching requirements found with previous results
                LOGGER.info(
                        "Skipping post DTLS probe {}. No applicable DTLS authentication bypass found.",
                        this.getClass().getSimpleName());
                return;
            }

            LOGGER.info("Attempting post DTLS probe {}", this.getClass().getSimpleName());

            TraceableConnection c = mitm(report);
            if (enableSrtp) {
                LOGGER.debug("MitM DTLS success. Initializing SRTP...");
                initSrtp();
                LOGGER.debug("SRTP init success");
            } else {
                LOGGER.debug("MitM DTLS success");
            }
            postDtlsCheck(c);
        } catch (Exception e) {
            if (!suppressErrorMessages) {
                LOGGER.warn("RtpProbe execution failed: ", e);
            }
        }
        report.addPostDtlsReport(mediaReport);
    }

    protected abstract void postDtlsCheck(TraceableConnection dtlsConnection);

    public WorkflowTrace getAuthBypassTrace() {
        return authBypassTrace;
    }

    /**
     * Sets the bypass for this probe to the first applicable DTLS authentication bypass. If none is
     * found null is set.
     */
    private void selectAuthBypass(WebRtcPlatformReport report) {

        List<AuthBypass> applicableBypasses =
                AuthBypassFactory.getApplicable(
                        report, requiresServerAuthBypass, requiresClientAuthBypass);

        if (applicableBypasses.isEmpty()) {
            this.authBypassTrace = null;
            this.authBypass = null;
            this.mediaReport.setTestable(false);
            return;
        }

        try {
            this.authBypass = applicableBypasses.get(0);
            LOGGER.debug("Choosing auth bypass: {}", authBypass.getClass().getSimpleName());
            this.authBypassTrace = authBypass.createTrace(report, getProxyConfiguration());
            this.authBypassTrace = finalizeBypassTrace(authBypassTrace);
            this.mediaReport.setBypassUsed(authBypass);
        } catch (Exception e) {
            this.authBypassTrace = null;
            this.authBypass = null;
            this.mediaReport.setTestable(false);
            throw e;
        }
    }

    /**
     * Method called directly after bypass trace creation. Overwrite with probe specific modifiers
     */
    public WorkflowTrace finalizeBypassTrace(WorkflowTrace authBypassTrace) {
        return authBypassTrace;
    }

    protected RtpCrypto getClientToAttackerRtpCrypto() {
        return clientToAttackerRtpCrypto;
    }

    protected RtpCrypto getAttackerToServerRtpCrypto() {
        return attackerToServerRtpCrypto;
    }

    public TlsContext getClientToAttackerTlsContext() {
        return clientToAttackerTlsContext;
    }

    public TlsContext getAttackerToServerTlsContext() {
        return attackerToServerTlsContext;
    }

    public static RtpCrypto createRtpCrypto(TlsContext tlsContext, boolean server)
            throws CryptoException {

        if (tlsContext == null) {
            LOGGER.debug(
                    "TLS Context given to initialize RTP session is null. Defaulting to NULL encryption/auth");
            return new SrtpNullHandler();
        }

        if (tlsContext.getMasterSecret() == null) {
            LOGGER.debug(
                    "TLS Context given to initialize RTP session contains no TLS Master Secret. Defaulting to NULL encryption/auth");
            return new SrtpNullHandler();
        }

        if (tlsContext.getSelectedSrtpProtectionProfile() == null) {
            LOGGER.debug(
                    "TLS Context given to initialize RTP session does not have an SRTP suite set, applying SRTP_AES128_CM_HMAC_SHA1_80");
            tlsContext.setSelectedSrtpProtectionProfile(
                    SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
        }

        return new SrtpHandler(tlsContext, server);
    }

    /**
     * Whether or not SRTP Handler should be initialized with key material from the handshake. Turn
     * off if no SRTP suite negotiated
     */
    public boolean isEnableSrtp() {
        return enableSrtp;
    }

    /**
     * Wether or not SRTP Handler should be initialized with key material from the handshake. Turn
     * off if no SRTP suite negotiated
     */
    public void setEnableSrtp(boolean enableSrtp) {
        this.enableSrtp = enableSrtp;
    }

    public void markNotTestable() {
        mediaReport.setTestable(false);
    }

    public MediaReport getMediaReport() {
        return mediaReport;
    }

    public boolean requiresClientAuthBypass() {
        return requiresClientAuthBypass;
    }

    public boolean requiresServerAuthBypass() {
        return requiresServerAuthBypass;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL, WebRtcProperties.PROVIDER_FUNCTIONAL);
    }

    public AuthBypass getAuthBypass() {
        return authBypass;
    }

    public boolean isSuppressErrorMessages() {
        return suppressErrorMessages;
    }

    public void setSuppressErrorMessages(boolean suppressErrorMessages) {
        this.suppressErrorMessages = suppressErrorMessages;
    }
}
