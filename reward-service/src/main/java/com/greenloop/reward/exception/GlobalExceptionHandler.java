package com.greenloop.reward.exception;

import com.greenloop.reward.dto.response.ApiResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ApiResponseDTO<Object>> handleBusinessException(
      BusinessException ex, HttpServletRequest request) {

    log.error("Business error [{}]: {}", ex.getErrorCode(), ex.getMessage());

    return ResponseEntity.status(ex.getStatus())
        .body(ApiResponseDTO.error(ex.getMessage(), ex.getStatus(), request.getRequestURI()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponseDTO<Object>> handleValidationExceptions(
      MethodArgumentNotValidException ex, HttpServletRequest request) {

    List<String> errors =
        ex.getBindingResult().getFieldErrors().stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .collect(Collectors.toList());

    log.error("Validation error on path {}: {}", request.getRequestURI(), errors);

    return ResponseEntity.badRequest()
        .body(
            ApiResponseDTO.error(
                "Validation failed", HttpStatus.BAD_REQUEST, request.getRequestURI(), errors));
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiResponseDTO<Object>> handleGenericException(
      Exception ex, HttpServletRequest request) {

    log.error("Unexpected error: ", ex);

    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(
            ApiResponseDTO.error(
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                request.getRequestURI()));
  }

  @ExceptionHandler(AuthorizationDeniedException.class)
  public ResponseEntity<ApiResponseDTO<Object>> handleAccessDeniedException(
      AuthorizationDeniedException ex, HttpServletRequest request) {

    log.warn("Access denied on path {}: {}", request.getRequestURI(), ex.getMessage());

    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(ApiResponseDTO.error("Access denied", HttpStatus.FORBIDDEN, request.getRequestURI()));
  }
}
