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
import org.openqa.selenium.Keys;
import org.openqa.selenium.interactions.Actions;

public class MattermostBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private String webPageUrl;

    private String username;

    private String password;

    private boolean pageOpen = false;

    public MattermostBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.MATTERMOST, capabilities, remoteWebDriverUrl, true);
        this.webPageUrl = targetConfig.getUrl();
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
        if (webPageUrl == null) {
            throw new RuntimeException("No URL for Mattermost specified");
        }
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!pageOpen) {
            openPage();
        }
        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        startCall();
    }

    public void startCall() {
        LOGGER.debug("Starting Mattermost call");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        Actions actions = new Actions(driver);
        actions.moveToLocation(1, 1).click().perform();
        actions.keyDown(Keys.ALT)
                .keyDown(Keys.CONTROL)
                .sendKeys("s")
                .keyUp(Keys.CONTROL)
                .keyUp(Keys.ALT)
                .perform();
    }

    public void endCall() {
        LOGGER.debug("Hangingup Mattermost call");
        Actions actions = new Actions(driver);
        actions.moveToLocation(1, 1).click().perform();
        actions.keyDown(Keys.LEFT_SHIFT)
                .keyDown(Keys.CONTROL)
                .sendKeys("l")
                .keyUp(Keys.CONTROL)
                .keyUp(Keys.LEFT_SHIFT)
                .perform();
        driver.navigate().refresh();
    }

    public void openPage() {
        LOGGER.debug("Opening Mattermost local page");
        pageOpen = true;
        driver.get(webPageUrl);
        LOGGER.debug("Selecting Web Version");
        waitAndClickCSS(
                "body > div:nth-child(1) > div:nth-child(1) > div:nth-child(2) > div:nth-child(2) > div:nth-child(2) > a:nth-child(2) > span:nth-child(1)");
        LOGGER.debug("Entering credentials");
        waitAndClickId("input_loginId");
        driver.findElement(By.id("input_loginId")).sendKeys(username);
        waitAndClickId("input_password-input");
        driver.findElement(By.id("input_password-input")).sendKeys(password);
        waitAndClickCSS("#saveSetting > span");
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
