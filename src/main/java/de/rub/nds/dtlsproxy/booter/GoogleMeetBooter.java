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
import org.openqa.selenium.Capabilities;

public class GoogleMeetBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String meetingUrl;

    public GoogleMeetBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.MEETS, capabilities, remoteWebDriverUrl, true);
        this.meetingUrl = targetConfig.getUrl();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {

        // Some notes to Google Meet (as of jan 2024):
        // ICE and DTLS starts in the preview page, even for unauthorized users
        // no second handshake takes place when pressing "join"

        LOGGER.debug("Starting DTLS connection");
        driver.get(meetingUrl);
    }
}
