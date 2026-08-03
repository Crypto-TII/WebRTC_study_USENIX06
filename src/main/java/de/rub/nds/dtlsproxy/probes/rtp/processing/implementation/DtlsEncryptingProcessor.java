/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.EncryptionProcessor;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;

public class DtlsEncryptingProcessor extends EncryptionProcessor<TlsContext, Record> {

    public DtlsEncryptingProcessor(TlsContext cryptoContext) {
        super(cryptoContext);
    }

    @Override
    protected Record encrypt(TlsContext cryptoContext, Record plaintext) {
        // Do nothing here. Encryption already takes place in the parsing stage.
        return plaintext;
    }

    @Override
    protected byte[] intermediateToCipherBytes(Record intermediate) {
        intermediate.setLength(intermediate.getProtocolMessageBytes().getOriginalValue().length);
        byte[] recordBytes = intermediate.getRecordSerializer().serialize();
        intermediate.setCompleteRecordBytes(recordBytes);
        return recordBytes;
    }

    @Override
    protected List<Record> parseToIntermediate(TlsContext cryptoContext, byte[] rawPacket) {
        CleanRecordByteSeperator separator =
                new CleanRecordByteSeperator(
                        cryptoContext.getChooser().getPeerReceiveLimit(),
                        new ByteArrayInputStream(rawPacket),
                        true,
                        false);
        List<Record> records = new LinkedList<>();
        separator.parse(records);

        RecordLayer recordLayer = cryptoContext.getRecordLayer();

        for (Record record : records) {
            if (recordLayer
                    .getEncryptor()
                    .getRecordCipher(recordLayer.getWriteEpoch())
                    .getState()
                    .getVersion()
                    .isDTLS()) {
                record.setEpoch(recordLayer.getWriteEpoch());
            }
            RecordPreparator preparator =
                    record.getRecordPreparator(
                            cryptoContext,
                            recordLayer.getEncryptor(),
                            recordLayer.getCompressor(),
                            ProtocolMessageType.APPLICATION_DATA);
            preparator.prepare();
            preparator.afterPrepare();
        }
        return records;
    }
}
