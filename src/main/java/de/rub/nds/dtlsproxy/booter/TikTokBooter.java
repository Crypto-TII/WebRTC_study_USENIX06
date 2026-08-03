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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.Dimension;

public class TikTokBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String username;
    private final String password;

    private boolean loggedIn;

    public TikTokBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.TIKTOK, capabilities, remoteWebDriverUrl, false);
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!loggedIn) {
            login();
            navigateToLive();
        } else {
            driver.navigate().refresh();
        }
    }

    public void navigateToLive() {
        LOGGER.debug("Opening live tab");
        driver.navigate().to("https://www.tiktok.com/live");
    }

    public void login() {
        LOGGER.debug("Logging into TikTok");
        driver.get("https://www.tiktok.com/login/phone-or-email/email");
        driver.manage().window().setSize(new Dimension(1204, 1339));
        driver.findElement(By.name("username")).click();
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.cssSelector(".tiktok-wv3bkt-InputContainer")).click();
        driver.findElement(By.cssSelector(".tiktok-wv3bkt-InputContainer")).sendKeys(password);
        waitAndClickCSS(".e1w6iovg0");
        // leave time for user to solve potential captcha
        try {
            Thread.sleep(30000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
