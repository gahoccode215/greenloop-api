package com.greenloop.event.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;

public class SecurityExceptionUtils {

  public static void writeErrorResponse(
      HttpServletRequest request, HttpServletResponse response, HttpStatus status, String message)
      throws IOException {

    Map<String, Object> body = new HashMap<>();
    body.put("success", false);
    body.put("message", message);
    body.put("statusCode", status.value());
    body.put("status", status.getReasonPhrase());
    body.put("path", request.getRequestURI());
    body.put("timestamp", LocalDateTime.now());

    response.setContentType("application/json");
    response.setStatus(status.value());
    new ObjectMapper().writeValue(response.getWriter(), body);
  }
}
