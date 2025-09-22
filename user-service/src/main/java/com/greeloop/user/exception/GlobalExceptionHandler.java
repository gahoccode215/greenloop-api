package com.greeloop.user.exception;

import com.greeloop.user.dto.response.ApiResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleBusinessException(
            BusinessException ex, HttpServletRequest request) {

        log.error("Business error [{}]: {}", ex.getErrorCode(), ex.getMessage());

        return ResponseEntity.status(ex.getHttpStatus()).body(
                ApiResponseDTO.error(ex.getMessage(), ex.getHttpStatus(), request.getRequestURI())
        );
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        List<String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());

        log.error("Validation error on path {}: {}", request.getRequestURI(), errors);

        return ResponseEntity.badRequest().body(
                ApiResponseDTO.error("Validation failed", HttpStatus.BAD_REQUEST, request.getRequestURI(), errors)
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleGenericException(
            Exception ex, HttpServletRequest request) {

        log.error("Unexpected error: ", ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ApiResponseDTO.error("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR, request.getRequestURI())
        );
    }
}

