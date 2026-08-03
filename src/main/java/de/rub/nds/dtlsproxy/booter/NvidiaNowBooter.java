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
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class NvidiaNowBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String username;
    private final String password;

    public NvidiaNowBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.NVIDIA_NOW, capabilities, remoteWebDriverUrl, true);
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");

        // Expect queue time during evening hours
        login();
        openPlayer();
    }

    public void openPlayer() {
        LOGGER.debug("Opening Nvidia Now web player");
        // starts CSGO. Expect queue time
        driver.findElement(By.cssSelector(".game-tile-button")).click();
        javascriptExecutor.executeScript("window.scrollTo(0,0)");
        driver.findElement(By.cssSelector(".launch-button > .mat-button-wrapper")).click();
    }

    public void login() {
        LOGGER.debug("Logging into Nvidia Now");
        LOGGER.debug("Opening page...");
        driver.get("https://play.geforcenow.com/mall/#/layout/games");
        driver.manage().window().setSize(new Dimension(842, 902));
        if (driver.findElement(By.cssSelector(".oobe-action-button > .mat-button-wrapper"))
                .isDisplayed()) {
            LOGGER.debug("Accepting terms...");
            try { // wait until terms appear and are clickable
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                // ignore
            }
            driver.findElement(By.cssSelector(".oobe-action-button > .mat-button-wrapper"))
                    .click(); // accept terms
            try { // wait until terms disappear
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                // ignore
            }
        }
        skipWalkthrough();
        LOGGER.debug("Pressing login button...");
        driver.findElement(By.cssSelector(".login")).click();
        LOGGER.debug("Entering Email...");
        driver.findElement(By.id("emailAddress")).click();
        driver.findElement(By.id("emailAddress")).sendKeys(username);
        driver.findElement(By.id("emailAddress")).sendKeys(Keys.ENTER);
        LOGGER.debug("Entering Password...");
        driver.findElement(By.id("signinPassword")).sendKeys(password);
        driver.findElement(By.id("passwordLoginButton")).click();
        // await user to confirm mail address
        // skipWalkthrough(); walkthrough appears sometimes here instead. Driver blocks
        // if no
        // walkthrough found so uncommented
    }

    private void skipWalkthrough() {
        LOGGER.debug("Skipping walkthrough...");
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(5));
            wait.until(
                    ExpectedConditions.presenceOfElementLocated(
                            (By.xpath("//span[contains(.,\'NEXT\')]"))));
            driver.findElement(By.xpath("//span[contains(.,\'NEXT\')]")).click(); // finish tutorial
            driver.findElement(By.xpath("//span[contains(.,\'GOT IT\')]")).click();
        } catch (NoSuchElementException execption) {
            LOGGER.debug("No walkthrough found");
        }
    }
}
