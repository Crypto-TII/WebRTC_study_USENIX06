/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.config;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class ConfigParser {

    /** context initialization is expensive, we need to do that only once */
    private static HashMap<Class<?>, JAXBContext> contexts = new HashMap<>();

    static synchronized <T> JAXBContext getJAXBContext(Class<T> clazz) throws JAXBException {
        if (!contexts.containsKey(clazz)) {
            contexts.put(clazz, JAXBContext.newInstance(clazz));
        }
        return contexts.get(clazz);
    }

    public static <T> T read(File file, Class<T> clazz)
            throws JAXBException, IOException, XMLStreamException {
        JAXBContext context = getJAXBContext(clazz);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(
                event -> {
                    // raise an Exception also on Warnings
                    return false;
                });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(new FileInputStream(file));
        return (T) unmarshaller.unmarshal(xsr);
    }
}
