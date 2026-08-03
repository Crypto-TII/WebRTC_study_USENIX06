/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption.implementation;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.util.MediaDumper;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import java.io.ByteArrayInputStream;

public class DtlsReencryptionHandler extends ReencryptionHandler<TlsContext, Record> {

    public DtlsReencryptionHandler(
            TlsContext clientToAttackerContext,
            TlsContext attackerToServerContext,
            HookedConnection connection,
            long duration,
            MediaReport report,
            MediaDumper serverToClientPlaintextDumper,
            MediaDumper clientToServerPlaintextDumper,
            boolean enableClientToAttackerEncryption,
            boolean enableAttackerToServerEncryption) {
        super(
                clientToAttackerContext,
                attackerToServerContext,
                connection,
                duration,
                report,
                MediaProtocol.DTLS,
                serverToClientPlaintextDumper,
                clientToServerPlaintextDumper,
                enableClientToAttackerEncryption,
                enableAttackerToServerEncryption);
    }

    @Override
    protected Thread createServerToClientThread() {
        return new Thread(
                createRunnable(
                        getConnection().getServerToClientDtlsAppData(),
                        true,
                        getConnection().getAttackerToClientTransport()::sendData),
                "DTLS serverToClient");
    }

    @Override
    protected Thread createClientToServerThread() {
        return new Thread(
                createRunnable(
                        getConnection().getClientToServerDtlsAppData(),
                        false,
                        getConnection().getAttackerToServerTransport()::sendData),
                "DTLS clientToServer");
    }

    @Override
    protected Record parseToIntermediate(TlsContext cryptoContext, byte[] rawPacket) {
        RecordParser parser =
                new RecordParser(
                        new ByteArrayInputStream(rawPacket),
                        cryptoContext.getLastRecordVersion(),
                        cryptoContext);
        Record toParseInto = new Record();
        parser.parse(toParseInto);
        return toParseInto;
    }

    @Override
    protected Record decrypt(TlsContext cryptoContext, Record ciphertext) {
        cryptoContext.getRecordLayer().getDecryptor().decrypt(ciphertext);
        return ciphertext;
    }

    @Override
    protected byte[] intermediateToPlainBytes(Record intermediate) {
        return intermediate.getCleanProtocolMessageBytes().getValue();
    }

    @Override
    protected Record encrypt(TlsContext cryptoContext, Record plaintext) {
        cryptoContext.getRecordLayer().getEncryptor().encrypt(plaintext);
        return plaintext;
    }

    @Override
    protected byte[] intermediateToCipherBytes(Record intermediate) {
        intermediate.setLength(intermediate.getProtocolMessageBytes().getOriginalValue().length);
        byte[] recordBytes = intermediate.getRecordSerializer().serialize();
        intermediate.setCompleteRecordBytes(recordBytes);
        return recordBytes;
    }
}
