package com.greeloop.user.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponseDTO<T> {
    private boolean success;
    private String message;
    private T data;
    private int statusCode;
    private String status;
    private String path;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    private List<String> errors;




    public static <T> ApiResponseDTO<T> success(String message, T data, HttpStatus status) {
        return ApiResponseDTO.<T>builder()
                .success(true)
                .message(message)
                .statusCode(status.value())
                .status(status.getReasonPhrase())
                .data(data)
                .build();
    }



    public static <T> ApiResponseDTO<T> error(String message, HttpStatus status, String path) {
        return ApiResponseDTO.<T>builder()
                .success(false)
                .message(message)
                .statusCode(status.value())
                .status(status.getReasonPhrase())
                .path(path)
                .build();
    }

    public static <T> ApiResponseDTO<T> error(String message, HttpStatus status, String path, List<String> errors) {
        return ApiResponseDTO.<T>builder()
                .success(false)
                .message(message)
                .statusCode(status.value())
                .status(status.getReasonPhrase())
                .path(path)
                .errors(errors)
                .build();
    }
}
