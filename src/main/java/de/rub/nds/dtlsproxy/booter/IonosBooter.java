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

public class IonosBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String url;

    public IonosBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.IONOS, capabilities, remoteWebDriverUrl, true);
        this.url = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");

        startCall();
    }

    public void startCall() {
        LOGGER.debug("Starting IONOS call");
        driver.get(url);
        driver.navigate().refresh();
        WebElement element = driver.findElement(By.cssSelector(".css-hh0z88-input"));
        Actions builder = new Actions(driver);
        builder.doubleClick(element).perform();
        driver.findElement(By.cssSelector(".css-hh0z88-input")).clear();
        driver.findElement(By.cssSelector(".css-hh0z88-input")).sendKeys("Webrtc-Test");
        waitAndClickCSS(".css-1hbmoh1-actionButton");
    }
}
