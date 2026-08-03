/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.config;

import de.rub.nds.dtlsproxy.enums.TargetName;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigList {

    @SuppressWarnings("unused")
    private static final Logger LOGGER = LogManager.getLogger();

    private List<TargetConfig> targetConfigList;

    public ConfigList() {
        targetConfigList = new LinkedList<>();
    }

    public List<TargetConfig> getTargetConfigList() {
        return targetConfigList;
    }

    public void setTargetConfigList(List<TargetConfig> targetConfigList) {
        this.targetConfigList = targetConfigList;
    }

    public void add(TargetConfig config) {
        targetConfigList.add(config);
    }

    public TargetConfig get(TargetName name) {
        for (TargetConfig config : targetConfigList) {
            if (config.getTargetName() == name) {
                return config;
            }
        }
        return null;
    }
}
