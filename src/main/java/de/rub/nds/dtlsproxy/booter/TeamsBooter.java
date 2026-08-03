/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
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
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;

public class TeamsBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String LOGIN_PAGE = ""; // TODO replace with login url

    private final String username;
    private final String password;
    private final String meetingUrl;

    public TeamsBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.MS_TEAMS, capabilities, remoteWebDriverUrl, true);
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
        this.meetingUrl = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        startCall();
    }

    public void startCall() {
        LOGGER.debug("Joining Microsoft Teams meeting");
        driver.navigate().to(meetingUrl);
        waitAndClickCSS("#prejoin-join-button");
        LOGGER.debug("Teams: Join now with microphone on");
    }

    public void login() {
        LOGGER.debug("Logging into Microsoft teams");
        driver.get(LOGIN_PAGE);
        wait.until(ExpectedConditions.elementToBeClickable(By.id("i0116")));
        driver.findElement(By.id("i0116")).sendKeys(username);
        wait.until(ExpectedConditions.elementToBeClickable(By.id("idSIButton9")));
        driver.findElement(By.id("idSIButton9")).click();
        wait.until(ExpectedConditions.elementToBeClickable(By.id("i0118")));
        driver.findElement(By.id("i0118")).sendKeys(password);
        wait.until(ExpectedConditions.elementToBeClickable(By.id("idSIButton9")));
        driver.findElement(By.id("idSIButton9")).click();
        wait.until(ExpectedConditions.elementToBeClickable(By.id("idSIButton9")));
        { // Link does not appear immediately
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            waitAndClickLinkText("Use the web app instead", 20); // many redirects, wait longer
            waitAndClickCSS(".icons-chat > .icons-filled");
            waitAndClickCSS(".cle-preview");
            WebElement element = driver.findElement(By.id("idSIButton9"));
            Actions builder = new Actions(driver);
            builder.moveToElement(element).perform();
        }
        wait.until(ExpectedConditions.elementToBeClickable(By.id("idBtn_Back")));
        driver.findElement(By.id("idBtn_Back")).click();
    }
}
