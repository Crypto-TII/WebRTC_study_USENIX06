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
import org.openqa.selenium.interactions.Actions;

public class ZohoBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();
    private final String url;

    private boolean pageOpen = false;

    public ZohoBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.ZOHO, capabilities, remoteWebDriverUrl, true);
        this.url = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!pageOpen) {
            LOGGER.debug("opening page and joining");
            driver.get(url);
            join();
        } else {
            LOGGER.debug("to meeting page");
            driver.navigate().to(url);
            join();
        }
    }

    public void join() {
        LOGGER.debug("clicking continue anyway");
        waitAndClickClass("btnContentText");
        LOGGER.debug("clicking username field");
        waitAndClickId("jpUserName");
        LOGGER.debug("entering username");
        driver.findElement(By.id("jpUserName")).sendKeys("webrtctest");
        LOGGER.debug("clicking join");
        waitAndClickId("jpContinueBtn");

        LOGGER.debug("clicking continue");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        new Actions(driver).moveToLocation(468, 541).click().perform();
        pageOpen = true;
    }

    @Override
    public boolean softReset() {
        LOGGER.debug("going to google");
        driver.navigate().to("https://www.google.com");
        return true;
    }

    @Override
    public void hardReset() {
        super.hardReset();
        pageOpen = false;
    }
}
