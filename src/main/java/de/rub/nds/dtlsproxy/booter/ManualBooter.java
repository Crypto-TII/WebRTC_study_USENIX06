/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.enums.TargetName;
import java.net.URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.Capabilities;

public class ManualBooter extends Booter {

    private int counter = 0;

    private static final Logger LOGGER = LogManager.getLogger();

    public ManualBooter(Capabilities capabilities, URL driverUrl) {
        super(TargetName.MANUAL, capabilities, driverUrl, true);
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.info("#########################################");
        LOGGER.info("TEST READY. Press call: {}", counter);
        LOGGER.info("#########################################");
        counter++;
    }
}
