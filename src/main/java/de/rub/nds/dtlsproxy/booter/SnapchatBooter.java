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
import org.openqa.selenium.Capabilities;

public class SnapchatBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    public SnapchatBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.SNAPCHAT, capabilities, remoteWebDriverUrl, false);
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        // Assume user logged in due to 2x two factor auth and 1x captcha
        call();
    }

    public void call() {
        LOGGER.debug("Calling snapchat contact");
        driver.get("https://web.snapchat.com/");
        waitAndClickCSS("#title-323cd721-a447-5940-9798-d57a55e9c835 > .FiLwP > span", 360);
        waitAndClickCSS(".sBHMP > svg");
    }
}
