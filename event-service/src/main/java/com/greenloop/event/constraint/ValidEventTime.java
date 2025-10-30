package com.greenloop.event.constraint;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EventTimeValidator.class)
public @interface ValidEventTime {
  String message() default
      "Invalid event time: startTime must be after now and endTime after startTime";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
