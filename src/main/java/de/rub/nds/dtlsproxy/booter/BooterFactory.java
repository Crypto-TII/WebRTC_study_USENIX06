/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.booter;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.config.TargetConfig;
import de.rub.nds.dtlsproxy.enums.Browser;
import de.rub.nds.dtlsproxy.enums.TargetName;
import org.openqa.selenium.Capabilities;

public class BooterFactory {

    private BooterFactory() {}

    public static Booter createBooter(
            TargetConfig targetConfig,
            Capabilities capabilities,
            ProxyConfiguration proxyConfiguration,
            Browser browser) {
        switch (targetConfig.getTargetName()) {
            case BIG_BLUE_BUTTON:
                return new BigBlueButtonBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case DISCORD:
                return new DiscordBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case MEETS:
                return new GoogleMeetBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case ZOOM:
                return new ZoomBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case SLACK:
                return new SlackBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case MS_TEAMS:
                return new TeamsBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case NVIDIA_NOW:
                return new NvidiaNowBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case TOKBOX:
                return new TokboxBooter(proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case TIKTOK:
                return new TikTokBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case SNAPCHAT:
                return new SnapchatBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case JANUS_CUSTOM:
                return new DamnVulnerableWebrtcBooter(
                        TargetName.JANUS_CUSTOM,
                        targetConfig.getUrl(),
                        proxyConfiguration.getRemoteWebDriverUrl(),
                        capabilities);
            case MANUAL:
                return new ManualBooter(capabilities, proxyConfiguration.getRemoteWebDriverUrl());
            case IONOS:
                return new IonosBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case MATTERMOST:
                return new MattermostBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case ZOHO:
                return new ZohoBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case WEBEX:
                return new WebexBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case EDUMEET:
                return new EduMeetBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case LIVEKIT:
                return new LiveKitBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case CLICKMEETING:
                return new ClickmeetingBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case CLOUDFLARE_REALTIME:
                return new RealtimekitBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            case NEXTCLOUD:
                return new NextcloudBooter(
                        targetConfig, proxyConfiguration.getRemoteWebDriverUrl(), capabilities);
            default:
                throw new UnsupportedOperationException(
                        "Could not create booter. Not supported: " + targetConfig.getTargetName());
        }
    }
}
