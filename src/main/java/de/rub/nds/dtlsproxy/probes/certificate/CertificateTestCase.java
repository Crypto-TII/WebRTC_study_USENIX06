/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.certificate;

import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public abstract class CertificateTestCase {

    public abstract TlsAction createSendCertificateAction(String connectionAlias);
}
