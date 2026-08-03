/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.DecryptionProcessor;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;

public class DtlsDecryptingProcessor extends DecryptionProcessor<TlsContext, Record> {

    public DtlsDecryptingProcessor(TlsContext cryptoContext) {
        super(cryptoContext);
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
    protected List<Record> parseToIntermediate(TlsContext cryptoContext, byte[] rawPacket) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(rawPacket);
        List<Record> records = new LinkedList<>();
        while (inputStream.available() > 0) {
            try {
                RecordParser parser =
                        new RecordParser(
                                inputStream, cryptoContext.getLastRecordVersion(), cryptoContext);
                Record toParseInto = new Record();
                parser.parse(toParseInto);
                records.add(toParseInto);
            } catch (Exception e) {
                break;
            }
        }

        return records;
    }
}
