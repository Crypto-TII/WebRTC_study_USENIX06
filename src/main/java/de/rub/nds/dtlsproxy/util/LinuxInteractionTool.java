/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import java.io.IOException;

public class LinuxInteractionTool {
    public static boolean isLinux() {
        return System.getProperty("os.name").toLowerCase().contains("linux");
    }

    public static boolean isLinuxToolAvailable(String tool) {
        if (isLinux()) {
            try {
                Process p = Runtime.getRuntime().exec("which " + tool);
                p.waitFor();
                return p.exitValue() == 0;
            } catch (IOException | InterruptedException e) {
                return false;
            }
        } else {
            return false;
        }
    }
}
