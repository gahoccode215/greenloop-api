package com.greenloop.event.constraint;

import com.greenloop.event.dto.request.EventRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.time.LocalDateTime;

public class EventTimeValidator implements ConstraintValidator<ValidEventTime, EventRequest> {

  @Override
  public boolean isValid(EventRequest request, ConstraintValidatorContext context) {
    if (request == null) return true;

    LocalDateTime now = LocalDateTime.now();
    boolean validStart = request.getStartTime() != null && request.getStartTime().isAfter(now);
    boolean validEnd =
        request.getEndTime() != null && request.getEndTime().isAfter(request.getStartTime());

    if (!validStart || !validEnd) {
      context.disableDefaultConstraintViolation();
      if (!validStart) {
        context
            .buildConstraintViolationWithTemplate("Start time must be after current time")
            .addPropertyNode("startTime")
            .addConstraintViolation();
      }
      if (!validEnd) {
        context
            .buildConstraintViolationWithTemplate("End time must be after start time")
            .addPropertyNode("endTime")
            .addConstraintViolation();
      }
      return false;
    }

    return true;
  }
}
