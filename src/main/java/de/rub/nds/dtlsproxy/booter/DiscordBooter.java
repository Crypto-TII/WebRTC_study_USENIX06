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

public class DiscordBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean initialized;

    private final String username;
    private final String password;

    public DiscordBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.DISCORD, capabilities, remoteWebDriverUrl, true);
        this.username = targetConfig.getUsername();
        this.password = targetConfig.getPassword();
        this.initialized = false;
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!initialized) {
            loginDiscord();
            initialized = true;
        } else {
            hangUp();
        }
        startCall();
    }

    public void startCall() {
        LOGGER.debug("Starting Discord call");
        javascriptExecutor.executeScript(
                "arguments[0].click();",
                driver.findElement(By.cssSelector(".typeVoice__86122 .name__4eb92")));
    }

    public void loginDiscord() {
        LOGGER.debug("Logging into Discord");
        driver.get("https://discord.com/login");
        waitAndClickId("uid_7"); // wait for page to load
        driver.findElement(By.id("uid_7")).sendKeys(username);
        driver.findElement(By.id("uid_9")).sendKeys(password);
        driver.findElement(By.xpath("//button[@type=\'submit\']")).click();
        waitAndClickCSS(".acronym_fb7739"); // hardcoded channel id
        javascriptExecutor.executeScript("window.scrollTo(0,0)");
    }

    private void hangUp() {
        LOGGER.debug("Hanging up Discord call");
        waitAndClickCSS("#channels");
        driver.findElement(
                        By.cssSelector(
                                ".flex_f5fbb7 > .flex_f5fbb7 > .button__4f306:nth-child(2) svg"))
                .click();
        // avoid rating call
        driver.navigate().refresh();
    }
}
