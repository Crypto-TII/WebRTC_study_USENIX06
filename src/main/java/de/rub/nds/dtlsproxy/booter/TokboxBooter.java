/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.enums.TargetName;
import java.net.URL;
import java.time.Duration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.Capabilities;

public class TokboxBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    public TokboxBooter(URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.TOKBOX, capabilities, remoteWebDriverUrl, true);
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(60));
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        LOGGER.debug("Opening ToxBox connectivity check site");
        driver.get("https://tokbox.com/developer/tools/precall/results?scalableVideo=true");
    }
}
