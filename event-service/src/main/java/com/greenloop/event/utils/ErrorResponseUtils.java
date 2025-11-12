package com.greenloop.event.utils;

import com.greenloop.event.dto.response.ApiResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class ErrorResponseUtils {

  private ErrorResponseUtils() {}

  public static <T> ResponseEntity<ApiResponseDTO<T>> buildNotFoundResponse(
      String message, String fallbackPath) {

    String path =
        Optional.ofNullable(RequestContextHolder.getRequestAttributes())
            .filter(ServletRequestAttributes.class::isInstance)
            .map(ServletRequestAttributes.class::cast)
            .map(ServletRequestAttributes::getRequest)
            .map(HttpServletRequest::getRequestURI)
            .orElse(fallbackPath);

    ApiResponseDTO<T> response = ApiResponseDTO.error(message, HttpStatus.NOT_FOUND, path);
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
  }

  public static <T> ResponseEntity<ApiResponseDTO<T>> buildForbiddenResponse(
      String message, String fallbackPath) {

    String path =
        Optional.ofNullable(RequestContextHolder.getRequestAttributes())
            .filter(ServletRequestAttributes.class::isInstance)
            .map(ServletRequestAttributes.class::cast)
            .map(ServletRequestAttributes::getRequest)
            .map(HttpServletRequest::getRequestURI)
            .orElse(fallbackPath);

    ApiResponseDTO<T> response = ApiResponseDTO.error(message, HttpStatus.FORBIDDEN, path);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
  }
}
