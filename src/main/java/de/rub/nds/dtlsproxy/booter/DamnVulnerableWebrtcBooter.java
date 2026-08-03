/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.enums.TargetName;
import java.net.URL;
import java.time.Duration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.Capabilities;

public class DamnVulnerableWebrtcBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private String webPageUrl;

    private boolean pageOpen = false;

    public DamnVulnerableWebrtcBooter(
            TargetName targetName,
            String webPageURL,
            URL remoteWebDriverUrl,
            Capabilities capabilities) {
        super(targetName, capabilities, remoteWebDriverUrl, true);
        this.webPageUrl = webPageURL;
        if (webPageUrl == null) {
            throw new RuntimeException("No URL for Janus webpage specified");
        }
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!pageOpen) {
            openPage();
        }
        startCall();
    }

    public void startCall() {
        LOGGER.debug("Starting DVWebRTC call");
        driver.findElement(By.id("startButton")).click();
    }

    public void endCall() {
        LOGGER.debug("Hangingup DVWebRTC call");
        driver.findElement(By.id("hangupButton")).click();
    }

    public void openPage() {
        LOGGER.debug("Opening DVWebRTC local page");
        pageOpen = true;
        driver.get(webPageUrl);
    }

    @Override
    public boolean softReset() {
        if (pageOpen) {
            endCall();
        }
        return true;
    }

    @Override
    public void hardReset() {
        super.hardReset();
        pageOpen = false;
    }
}
