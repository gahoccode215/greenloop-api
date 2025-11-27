package com.greenloop.user.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum BlogStatus {
    DRAFT("Bản nháp"),
    PUBLISHED("Đã công khai"),
    HIDDEN("Đã ẩn");

    private final String displayName;

    BlogStatus(String displayName) {
        this.displayName = displayName;
    }

    @JsonValue
    public String getDisplayName() {
        return displayName;
    }

    public String getCode() {
        return this.name();
    }
}
