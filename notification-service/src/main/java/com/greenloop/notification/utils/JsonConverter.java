package com.greenloop.notification.utils;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.io.IOException;
import java.util.HashMap;

@Converter(autoApply = true)
public class JsonConverter implements AttributeConverter<HashMap<String, String>, String> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(HashMap<String, String> attribute) {
        try {
            return attribute == null ? null : objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error converting map to JSON", e);
        }
    }

    @Override
    public HashMap<String, String> convertToEntityAttribute(String dbData) {
        try {
            return dbData == null
                    ? null
                    : objectMapper.readValue(dbData, new TypeReference<HashMap<String, String>>() {
            });
        } catch (IOException e) {
            throw new RuntimeException("Error reading JSON from DB", e);
        }
    }
}

