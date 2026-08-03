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
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.FluentWait;
import org.openqa.selenium.support.ui.WebDriverWait;

public abstract class Booter {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int DEFAULT_WAIT_TIME_SECONDS = 60;

    protected WebDriver driver;

    protected JavascriptExecutor javascriptExecutor;

    protected final TargetName targetName;

    protected FluentWait<WebDriver> wait;

    private URL driverUrl;

    private Capabilities capabilities;

    public Booter(
            TargetName targetName, Capabilities capabilities, URL driverUrl, boolean incognito) {
        if (incognito) {
            if (capabilities instanceof ChromeOptions) {
                ((ChromeOptions) capabilities).addArguments("--incognito");
            } else if (capabilities instanceof EdgeOptions) {
                ((EdgeOptions) capabilities).addArguments("-inprivate");
            } else {
                // assume Opera
                try {
                    Class.forName("org.openqa.selenium.opera.OperaOptions")
                            .getMethod("addArguments", List.class)
                            .invoke(capabilities, Arrays.asList("--private"));
                } catch (Exception e) {
                    // Opera not supported by selenium version or Capabilities
                    LOGGER.error(e);
                }
            }
        }
        this.targetName = targetName;
        if (!(this instanceof ManualBooter)) {

            this.driver = new RemoteWebDriver(driverUrl, capabilities, false);
            this.javascriptExecutor = (JavascriptExecutor) driver;
            this.wait =
                    new FluentWait<>(driver)
                            .withTimeout(Duration.ofSeconds(DEFAULT_WAIT_TIME_SECONDS))
                            .pollingEvery(Duration.ofMillis(200))
                            .ignoring(NoSuchElementException.class);
            this.driverUrl = driverUrl;
            this.capabilities = capabilities;
        }
    }

    public void waitAndClickCSS(String cssId) {
        waitAndClickCSS(cssId, DEFAULT_WAIT_TIME_SECONDS);
    }

    public void waitAndClickLinkText(String linkText) {
        waitAndClickLinkText(linkText, DEFAULT_WAIT_TIME_SECONDS);
    }

    public void waitAndClickId(String id) {
        waitAndClickId(id, DEFAULT_WAIT_TIME_SECONDS);
    }

    public void waitAndClickClass(String className) {
        waitAndClickClass(className, DEFAULT_WAIT_TIME_SECONDS);
    }

    public void waitAndClickCSS(String cssId, int seconds) {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(seconds));
        wait.until(ExpectedConditions.presenceOfElementLocated((By.cssSelector(cssId))));
        driver.findElement(By.cssSelector(cssId)).click();
    }

    public void waitAndClickLinkText(String linkText, int seconds) {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(seconds));
        wait.until(ExpectedConditions.presenceOfElementLocated((By.linkText(linkText))));
        driver.findElement(By.linkText(linkText)).click();
    }

    public void waitAndClickId(String id, int seconds) {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(seconds));
        wait.until(ExpectedConditions.presenceOfElementLocated((By.id(id))));
        driver.findElement(By.id(id)).click();
    }

    public void waitAndClickClass(String className, int seconds) {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(seconds));
        wait.until(ExpectedConditions.presenceOfElementLocated((By.className(className))));
        wait.until(ExpectedConditions.elementToBeClickable((By.className(className))));
        forceClick(By.className(className));
    }

    public void forceClick(By selector) {
        Point location = driver.findElement(selector).getLocation();
        Actions actions = new Actions(driver);
        actions.moveToLocation(location.x, location.y).click().perform();
    }

    /**
     * Clicks on the specified pixel, relative to the top left page corner
     *
     * @param x
     * @param y
     */
    public void clickPagePosition(int x, int y) {
        new Actions(driver).moveToLocation(0, 0).moveByOffset(x, y).click().perform();
    }

    public abstract void startDtlsConnection();

    public String takeBase64ScreenShot() {
        TakesScreenshot screenShotTaker = ((TakesScreenshot) driver);
        return screenShotTaker.getScreenshotAs(OutputType.BASE64);
    }

    /** Performs a hard reset by reestablishing the driver connection */
    public void hardReset() {
        if (driver != null) {

            this.driver.close();
            this.driver.quit();
            this.driver = new RemoteWebDriver(driverUrl, capabilities, false);
            this.javascriptExecutor = (JavascriptExecutor) driver;
            this.wait =
                    new FluentWait<>(driver)
                            .withTimeout(Duration.ofSeconds(DEFAULT_WAIT_TIME_SECONDS))
                            .pollingEvery(Duration.ofMillis(200))
                            .ignoring(NoSuchElementException.class);
        }
    }

    /**
     * Will reset the website only without closing the driver/window
     *
     * @return true if implemented by the current booter
     */
    public boolean softReset() {
        return false;
    }

    public String getTargetName() {
        return targetName.name();
    }

    public void close() {
        if (driver != null) {
            driver.close();
            driver.quit();
        }
    }

    /**
     * runs a JS hook into setRemoteDescription and setLocalDescription functions that drops TCP ICE
     * candidates from the SDP
     */
    protected void hookICEFilter() {
        final String script =
                "// Hook into the WebRTC setRemoteDescription and setLocalDescription methods\n"
                        + "(function() {\n"
                        + "    const originalSetRemoteDescription = RTCPeerConnection.prototype.setRemoteDescription;\n"
                        + "    const originalSetLocalDescription = RTCPeerConnection.prototype.setLocalDescription;\n"
                        + "\n"
                        + "    // Utility function to filter out TCP ICE candidates from SDP\n"
                        + "    function filterTcpCandidates(sdp) {\n"
                        + "        const lines = sdp.split('\\n');\n"
                        + "        const filteredLines = lines.filter(line => !line.includes(\"a=candidate\") || !line.includes(\"TCP\"));\n"
                        + "        return filteredLines.join('\\n');\n"
                        + "    }\n"
                        + "\n"
                        + "    // Override setRemoteDescription\n"
                        + "    RTCPeerConnection.prototype.setRemoteDescription = async function(description) {\n"
                        + "        console.log(\"Original Remote SDP:\", description.sdp);\n"
                        + "\n"
                        + "        if (description && description.sdp) {\n"
                        + "            description.sdp = filterTcpCandidates(description.sdp);\n"
                        + "            console.log(\"Modified Remote SDP:\", description.sdp);\n"
                        + "        }\n"
                        + "\n"
                        + "        return originalSetRemoteDescription.apply(this, arguments);\n"
                        + "    };\n"
                        + "\n"
                        + "    // Override setLocalDescription\n"
                        + "    RTCPeerConnection.prototype.setLocalDescription = async function(description) {\n"
                        + "        console.log(\"Original Local SDP:\", description.sdp);\n"
                        + "\n"
                        + "        if (description && description.sdp) {\n"
                        + "            description.sdp = filterTcpCandidates(description.sdp);\n"
                        + "            console.log(\"Modified Local SDP:\", description.sdp);\n"
                        + "        }\n"
                        + "\n"
                        + "        return originalSetLocalDescription.apply(this, arguments);\n"
                        + "    };\n"
                        + "\n"
                        + "    console.log(\"WebRTC SDP filtering hook applied: TCP candidates will be removed.\");\n"
                        + "})();";
        javascriptExecutor.executeScript(script);
    }
}
