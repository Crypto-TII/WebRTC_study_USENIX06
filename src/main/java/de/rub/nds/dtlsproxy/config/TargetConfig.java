/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.config;

import de.rub.nds.dtlsproxy.enums.Browser;
import de.rub.nds.dtlsproxy.enums.TargetName;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TargetConfig {

    /** Service ID */
    private TargetName targetName;

    /** Browsers running the service */
    private Browser[] browsers;

    /** Service URL to be used by a booter if required */
    private String url;

    /** Service username to be used by a booter if required */
    private String username;

    /** Service password to be used by a booter if required */
    private String password;

    @SuppressWarnings("unused")
    private TargetConfig() {}

    public TargetConfig(
            TargetName targetName,
            Browser[] browsers,
            String url,
            String username,
            String password) {
        this.targetName = targetName;
        this.url = url;
        this.username = username;
        this.password = password;
        this.browsers = browsers;
    }

    public TargetName getTargetName() {
        return targetName;
    }

    public void setTargetName(TargetName targetName) {
        this.targetName = targetName;
    }

    public Browser[] getBrowsers() {
        return browsers;
    }

    public void setBrowsers(Browser[] browsers) {
        this.browsers = browsers;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Target Name: ");
        builder.append(targetName);
        builder.append("\n");
        builder.append("Browsers: ");
        if (browsers == null) {
            builder.append("none");
        } else {
            builder.append(
                    Arrays.stream(browsers).map(Enum::name).collect(Collectors.joining(", ")));
        }
        return builder.toString();
    }
}
