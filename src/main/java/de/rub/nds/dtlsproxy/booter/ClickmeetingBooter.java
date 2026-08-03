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
import org.openqa.selenium.Keys;

public class ClickmeetingBooter extends Booter {
    private static final Logger LOGGER = LogManager.getLogger();

    private final String url;

    public ClickmeetingBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.CLICKMEETING, capabilities, remoteWebDriverUrl, true);
        this.url = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");

        // Assume browser session already declined cookies and accepted policy etc

        driver.get(url);

        driver.findElement(By.id("conference_nickname")).sendKeys("webrtctest");
        driver.findElement(By.id("conference_email")).sendKeys("webrtctest@web.de");
        driver.findElement(By.id("conference_email")).sendKeys(Keys.ENTER);
    }
}
