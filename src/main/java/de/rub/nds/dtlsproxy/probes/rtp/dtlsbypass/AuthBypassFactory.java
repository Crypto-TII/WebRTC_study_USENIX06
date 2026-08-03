/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass;

import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class AuthBypassFactory {

    private AuthBypassFactory() {
        // Hide implicit public constructor
    }

    private static final List<AuthBypass> ALL_BYPASSES = new ArrayList<>();

    static {
        // sorted for priority
        ALL_BYPASSES.add(new DoubleLeafClientCertBypass(false));
        ALL_BYPASSES.add(new DoubleLeafClientCertBypass(true));
        ALL_BYPASSES.add(new DoubleLeafServerCertBypass(false));
        ALL_BYPASSES.add(new DoubleLeafServerCertBypass(true));
        ALL_BYPASSES.add(new BogusServerCertBypass());
        ALL_BYPASSES.add(new BogusClientCertBypass());
        ALL_BYPASSES.add(new EmptyClientCertBypass());
        ALL_BYPASSES.add(new NoCertRequestBypass());
        ALL_BYPASSES.add(new TrustedClientCertBypass());
        ALL_BYPASSES.add(new TrustedServerCertBypass());
        ALL_BYPASSES.add(new MimicryClientCertBypass());
        ALL_BYPASSES.add(new MimicryServerCertBypass());

        ALL_BYPASSES.add(new NoCertRequestBogusServerCertBypass());
        ALL_BYPASSES.add(new EmptyClientCertBogusServerCertBypass());
        ALL_BYPASSES.add(new BothBogusCertBypass());
        ALL_BYPASSES.add(new DoubleLeafClientCertBogusServerCertBypass(false));
        ALL_BYPASSES.add(new BogusClientCertDoubleLeafServerCertBypass(false));
        ALL_BYPASSES.add(new DoubleLeafClientCertBogusServerCertBypass(true));
        ALL_BYPASSES.add(new BogusClientCertDoubleLeafServerCertBypass(true));
        ALL_BYPASSES.add(new MimicryClientCertBogusServerCertBypass());
        ALL_BYPASSES.add(new BogusClientCertMimicryServerCertBypass());
        ALL_BYPASSES.add(new TrustedClientCertBogusServerCertBypass());
        ALL_BYPASSES.add(new BogusClientCertTrustedServerCertBypass());
    }

    /**
     * Returns all probes that meet atleast the bypass requirements and are applicable to the report
     *
     * @param report report results collected
     * @param mustBypassServerAuth
     * @param mustBypassClientAuth
     * @return
     */
    public static List<AuthBypass> getApplicable(
            WebRtcPlatformReport report,
            boolean mustBypassServerAuth,
            boolean mustBypassClientAuth) {
        List<AuthBypass> list = getApplicable(report);

        return list.stream()
                .filter(
                        authBypass -> {
                            if (mustBypassServerAuth && !authBypass.isBypassesServerAuth()) {
                                return false;
                            }
                            if (mustBypassClientAuth && !authBypass.isBypassesClientAuth()) {
                                return false;
                            }
                            return true;
                        })
                .collect(Collectors.toList());
    }

    public static List<AuthBypass> getApplicable(WebRtcPlatformReport report) {
        List<AuthBypass> list = new LinkedList<>();

        // add all applicable
        for (AuthBypass bypass : ALL_BYPASSES) {
            if (bypass.isApplicable(report)) {
                list.add(bypass);
            }
        }

        return list;
    }
}
