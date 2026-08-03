/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.report;

import java.util.LinkedList;
import java.util.List;

public class WebRtcFullReport {

    private List<WebRtcPlatformReport> platformReportList;

    public WebRtcFullReport() {
        platformReportList = new LinkedList<>();
    }

    public void addReport(WebRtcPlatformReport platformReport) {
        platformReportList.add(platformReport);
    }

    public String getReport() {
        StringBuilder builder = new StringBuilder("### FULL REPORT ###\n");
        builder.append("---------\n");
        builder.append("Total reports: " + platformReportList.size() + "\n");
        builder.append("------------------------------------------------\n");
        for (WebRtcPlatformReport report : platformReportList) {
            builder.append(report.toString());
        }
        return builder.toString();
    }

    public List<WebRtcPlatformReport> getPlatformReportList() {
        return platformReportList;
    }
}
