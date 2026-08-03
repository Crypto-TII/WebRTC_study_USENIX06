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
import java.net.URL;
import java.time.Duration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.Capabilities;

public class EduMeetBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private String webPageUrl;

    private boolean pageOpen = false;

    public EduMeetBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(targetConfig.getTargetName(), capabilities, remoteWebDriverUrl, true);
        this.webPageUrl = targetConfig.getUrl();
        if (webPageUrl == null) {
            throw new RuntimeException("No URL for EduMeet webpage specified");
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
        LOGGER.debug("Starting EduMeet call");
        // waitAndClickCSS("#\\3Ar12\\3A");
        // driver.findElement(By.cssSelector("#\\3Ar12\\3A")).sendKeys("WebRTC-Test");
        driver.navigate().to(webPageUrl);
        driver.findElement(By.cssSelector(".MuiButton-sizeSmall")).click();
    }

    public void endCall() {
        LOGGER.debug("Hangingup EduMeet call");
        driver.findElement(By.cssSelector(".MuiButton-root")).click();
        waitAndClickCSS(".MuiButton-sizeSmall");
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
        }
    }

    public void openPage() {
        LOGGER.debug("Opening EduMeet page");
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
