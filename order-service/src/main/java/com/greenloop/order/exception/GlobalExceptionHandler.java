package com.greenloop.order.exception;

import com.greenloop.order.dto.response.ApiResponseDTO;
import feign.FeignException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleBusinessException(
            BusinessException ex, HttpServletRequest request) {

        log.error("Business error [{}]: {}", ex.getErrorCode(), ex.getMessage());

        return ResponseEntity.status(ex.getHttpStatus())
                .body(ApiResponseDTO.error(
                        ex.getMessage(),
                        ex.getHttpStatus(),
                        request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleValidationException(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        List<String> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());

        log.warn("Validation failed: {}", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDTO.error(
                        "Validation failed",
                        HttpStatus.BAD_REQUEST,
                        request.getRequestURI(),
                        errors));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO<Void>> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDTO.error(
                        "Internal server error: " + ex.getMessage(),
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        request.getRequestURI()
                ));
    }



    @ExceptionHandler(FeignException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleFeignException(
            FeignException ex,
            HttpServletRequest request) {

        log.error("Feign client error: status={}, message={}", ex.status(), ex.getMessage());

        HttpStatus status = HttpStatus.valueOf(ex.status());

        return ResponseEntity.status(status)
                .body(ApiResponseDTO.error(
                        "Service communication error: " + ex.getMessage(),
                        status,
                        request.getRequestURI()));
    }
}
