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
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.interactions.Actions;

public class LiveKitBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean pageOpen = false;

    public LiveKitBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.LIVEKIT, capabilities, remoteWebDriverUrl, false);
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        if (!pageOpen) {
            driver.get("https://livekit.io/");
            pageOpen = true;
        }
        Actions actions = new Actions(driver);
        actions.moveToLocation(1, 1).click().perform();
        actions.sendKeys("t").perform();
    }

    @Override
    public boolean softReset() {
        if (pageOpen) {
            driver.navigate().refresh();
        }
        return true;
    }

    @Override
    public void hardReset() {
        super.hardReset();
        pageOpen = false;
    }
}
