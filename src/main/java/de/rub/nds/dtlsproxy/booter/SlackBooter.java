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
import org.openqa.selenium.Dimension;
import org.openqa.selenium.Keys;
import org.openqa.selenium.interactions.Actions;

public class SlackBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String username;
    private final String password;
    private final String workspace;
    private boolean pageOpen = false;

    public SlackBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.SLACK, capabilities, remoteWebDriverUrl, false);
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
        this.workspace = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        openSlack();
        toggleHuddle();
    }

    public void toggleHuddle() {
        LOGGER.debug("Toggeling Slack huddle (shift+alt+ctrl+h)");
        javascriptExecutor.executeScript("window.scrollTo(0,0)");
        // avoid toggle spam check with thread sleep
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
        }
        Actions actions = new Actions(driver);
        actions.moveToLocation(1, 1).click().perform();
        actions.keyDown(Keys.LEFT_SHIFT)
                .keyDown(Keys.ALT)
                .keyDown(Keys.CONTROL)
                .sendKeys("h")
                .keyUp(Keys.CONTROL)
                .keyUp(Keys.ALT)
                .keyUp(Keys.LEFT_SHIFT)
                .perform();
        javascriptExecutor.executeScript("window.scrollTo(0,0)");
        LOGGER.debug("Slack huddle toggled");
    }

    public void openSlack() {
        LOGGER.debug("Opening Slack workspace");
        driver.get("https://slack.com/signin#/signin");
        driver.manage().window().setSize(new Dimension(842, 902));
        // Assume cookies already declined
        // waitAndClickId("onetrust-reject-all-handler");
        waitAndClickCSS(".bold:nth-child(1)");
        waitAndClickId("domain");
        driver.findElement(By.id("domain")).sendKeys(workspace);
        waitAndClickCSS(".c-button");

        // wait for forwarding to complete
        try {
            Thread.sleep(15000);
        } catch (InterruptedException e) {
        }
        if (!driver.getCurrentUrl().startsWith("https://app.slack.com")) {
            // assume login page displayed
            enterCredentials();
        }
        pageOpen = true;
    }

    private void enterCredentials() {
        LOGGER.debug("Entering Slack credentials");
        waitAndClickLinkText("sign in with a password instead");
        waitAndClickId("email");
        driver.findElement(By.id("email")).sendKeys(username);
        waitAndClickId("password");
        driver.findElement(By.id("password")).sendKeys(password);
        waitAndClickId("signin_btn");
    }

    @Override
    public boolean softReset() {
        if (pageOpen) {
            toggleHuddle();
        }
        return true;
    }

    @Override
    public void hardReset() {
        super.hardReset();
        pageOpen = false;
    }
}
