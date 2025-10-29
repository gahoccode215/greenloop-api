package com.greenloop.event.enums;

public enum EventStatus {
  CREATED("Event has been created"),
  PUBLISHED("Event is published and visible"),
  UPCOMING("Event is scheduled and approaching"),
  ONGOING("Event is currently happening"),
  CLOSED("Event has ended"),
  CANCELED("Event has been canceled");

  private final String description;

  EventStatus(String description) {
    this.description = description;
  }

  public String getDescription() {
    return description;
  }
}
