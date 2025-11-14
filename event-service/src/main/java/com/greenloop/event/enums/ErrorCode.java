package com.greenloop.event.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    CONVERT_GOOGLE_PLACE_ERROR("1000", "Convert Json Fail", HttpStatus.BAD_REQUEST),
    UPLOAD_IMAGE_ERROR("1001", "Upload Image Fail", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_NOT_FOUND("1002", "Event Not Found", HttpStatus.NOT_FOUND),
    EVENT_CODE_ALREADY_EXISTS("1003", "Event Code Already Exists", HttpStatus.BAD_REQUEST),
    EVENT_CODE_GENERATION_ERROR(
            "1004", "Event Code Generation Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_CREATION_ERROR("1005", "Event Creation Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_UPDATE_ERROR("1006", "Event Update Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_DELETION_ERROR("1007", "Event Deletion Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_STATUS_UPDATE_ERROR("1008", "Event Status Update Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_IMAGE_UPLOAD_ERROR("1009", "Event Image Upload Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_IMAGE_DELETION_ERROR(
            "1010", "Event Image Deletion Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_LOCATION_UPDATE_ERROR(
            "1011", "Event Location Update Error", HttpStatus.INTERNAL_SERVER_ERROR),
    EVENT_START_TIME_PAST("1012", "Event Start Time Cannot Be in the Past", HttpStatus.BAD_REQUEST),
    EVENT_END_TIME_PAST("1013", "Event End Time Cannot Be in the Past", HttpStatus.BAD_REQUEST),
    EVENT_END_TIME_BEFORE_START(
            "1014", "Event End Time Cannot Be Before Start Time", HttpStatus.BAD_REQUEST),
    EVENT_LOCATION_NOT_FOUND("1015", "Event Location Not Found", HttpStatus.NOT_FOUND),
    INVALID_EVENT_STATUS("1016", "Invalid Event Status", HttpStatus.BAD_REQUEST),

    // Event Staff Assignment Errors
    STAFF_ALREADY_ASSIGNED("2000", "Staff Already Assigned to Event", HttpStatus.BAD_REQUEST),
    STORE_MANAGER_ALREADY_ASSIGNED(
            "2001", "Store Manager Already Assigned to Event", HttpStatus.BAD_REQUEST),
    INVALID_ROLE("2002", "Invalid Role for Assignment", HttpStatus.BAD_REQUEST),

    // User Related Errors
    USER_NOT_FOUND("3000", "User Not Found", HttpStatus.NOT_FOUND),
    ALREADY_REGISTERED("3001", "User Already Registered to Event", HttpStatus.BAD_REQUEST),
    REGISTRATION_NOT_FOUND("3002", "Event Registration Not Found", HttpStatus.NOT_FOUND),
    UNAUTHORIZED_ACCESS("3003", "Unauthorized Access", HttpStatus.UNAUTHORIZED);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
