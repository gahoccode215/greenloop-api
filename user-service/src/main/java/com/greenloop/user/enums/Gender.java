package com.greenloop.user.enums;

public enum Gender {
  MALE,
  FEMALE,
  UNKNOWN;

  public boolean isMale() {
    return this == MALE;
  }

  public boolean isFemale() {
    return this == FEMALE;
  }

  public boolean isUnknown() {
    return this == UNKNOWN;
  }
}
