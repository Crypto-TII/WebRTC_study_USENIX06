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

public class WebexBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int POS_X_JOIN_BUTTON = 876;
    private static final int POS_Y_JOIN_BUTTON = 894;

    private String url;

    public WebexBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.DISCORD, capabilities, remoteWebDriverUrl, false);
        this.url = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Attempting Webex DTLS connection");

        // open page
        driver.get(url);

        // click on "in bowser"
        waitAndClickId("broadcom-center-right");

        // wait for mic to be ready
        try {
            Thread.sleep(9000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        clickPagePosition(POS_X_JOIN_BUTTON, POS_Y_JOIN_BUTTON);
    }
}
