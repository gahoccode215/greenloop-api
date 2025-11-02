package com.greenloop.event.enums;

public enum RegistrationStatus {
  BOOKED("User has a booking"),
  CANCELED("User canceled the booking"),
  ATTENDED("User attended the event"),
  NO_SHOW("User did not show up for the event"),
  BLOCKED("User is blocked from registering");

  private final String description;

  RegistrationStatus(String description) {
    this.description = description;
  }

  public String getDescription() {
    return description;
  }
}
