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

public class NextcloudBooter extends Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String url;

    boolean open = true;

    public NextcloudBooter(
            TargetConfig targetConfig, URL remoteWebDriverUrl, Capabilities capabilities) {
        super(TargetName.NEXTCLOUD, capabilities, remoteWebDriverUrl, false);
        this.url = targetConfig.getUrl();
    }

    @Override
    public void startDtlsConnection() {
        LOGGER.debug("Starting DTLS connection");
        driver.get(url);
        hookICEFilter();
        waitAndClickId("call_button");
        hookICEFilter();
        open = true;
    }

    @Override
    public boolean softReset() {
        driver.navigate().refresh();
        return true;
    }
}
