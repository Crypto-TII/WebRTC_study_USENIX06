/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.config.TargetConfig;
import de.rub.nds.dtlsproxy.enums.TargetName;
import java.net.URL;
import java.time.Duration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.Capabilities;

public class BigBlueButtonBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String url;

    private boolean pageOpen = false;

    public BigBlueButtonBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.BIG_BLUE_BUTTON, capabilities, remoteWebDriverUrl, true);
        this.url = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        joinRoom();
    }

    public void joinRoom() {
        LOGGER.debug("Joining BigBlueButtom room");
        if (!pageOpen) {
            driver.get(url);
            pageOpen = true;
            waitAndClickId("joinFormName");
            driver.findElement(By.id("joinFormName")).sendKeys("test");
            // waitAndClickId("consentCheck"); // 2.7.x only
            waitAndClickCSS(".float-end");
            hookICEFilter();
            // waitAndClickCSS(".icon-bbb-unmute"); // 2.7.x only
            // waitAndClickCSS(".sc-dlVxhl:nth-child(2) > .sc-ieecCq"); // 2.7.x
            // waitAndClickCSS(".sc-tagGq:nth-child(2) > .sc-jxOSlx"); // 3.x
        }
    }

    @Override
    public boolean softReset() {
        if (pageOpen) {
            driver.navigate().refresh();
        }
        return true;
    }

    @Override
    public void hardReset() {
        super.hardReset();
        pageOpen = false;
    }
}
