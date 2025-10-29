package com.greenloop.event.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.greenloop.event.enums.ErrorCode;
import com.greenloop.event.exception.BusinessException;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.io.IOException;
import java.util.HashMap;
import lombok.RequiredArgsConstructor;

@Converter(autoApply = true)
@RequiredArgsConstructor
public class JsonConverter implements AttributeConverter<HashMap<String, String>, String> {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public String convertToDatabaseColumn(HashMap<String, String> attribute) {
    try {
      return objectMapper.writeValueAsString(attribute);
    } catch (JsonProcessingException e) {
      throw new BusinessException(ErrorCode.CONVERT_GOOGLE_PLACE_ERROR) {};
    }
  }

  @Override
  public HashMap<String, String> convertToEntityAttribute(String dbData) {
    if (dbData == null) return new HashMap<>();
    try {
      return objectMapper.readValue(dbData, new TypeReference<HashMap<String, String>>() {});
    } catch (IOException e) {
      throw new BusinessException(ErrorCode.CONVERT_GOOGLE_PLACE_ERROR);
    }
  }
}
