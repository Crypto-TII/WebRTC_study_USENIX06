/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.post.PostAnalyzer;
import de.rub.nds.dtlsproxy.provider.ConnectionProvider;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;

public class WebrtcExecutionContext {

    private ProxyConfiguration proxyConfiguration;

    private PostAnalyzer postAnalyzer;

    private WebRtcPlatformReport platformReport;

    private ConnectionProvider connectionProvider;

    private SessionManager sessionManager;

    public WebrtcExecutionContext(
            ProxyConfiguration proxyConfiguration,
            WebRtcPlatformReport platformReport,
            ConnectionProvider connectionProvider,
            SessionManager sessionManager) {
        this.proxyConfiguration = proxyConfiguration;
        this.platformReport = platformReport;
        this.postAnalyzer = new PostAnalyzer(platformReport);
        this.connectionProvider = connectionProvider;
        this.sessionManager = sessionManager;
    }

    public ProxyConfiguration getProxyConfiguration() {
        return proxyConfiguration;
    }

    public PostAnalyzer getPostAnalyzer() {
        return postAnalyzer;
    }

    public WebRtcPlatformReport getPlatformReport() {
        return platformReport;
    }

    public ConnectionProvider getConnectionProvider() {
        return connectionProvider;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }
}
