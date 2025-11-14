package com.greenloop.product.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    PRODUCT_NOT_FOUND("PROD_001", "Product not found", HttpStatus.NOT_FOUND),
    PRODUCT_ALREADY_EXISTS("PROD_002", "Product with the given identifier already exists", HttpStatus.CONFLICT),
    INVALID_PRODUCT_DATA("PROD_003", "Invalid product data provided", HttpStatus.BAD_REQUEST),
    UPLOAD_IMAGE_ERROR("PROD_004", "Error occurred while uploading image", HttpStatus.INTERNAL_SERVER_ERROR),
    CATEGORY_NOT_FOUND("PROD_005", "Category not found", HttpStatus.NOT_FOUND),
    ECO_POINT_VALUE_OUT_OF_BOUNDS("PROD_006", "Eco point value is out of bounds", HttpStatus.BAD_REQUEST),
    EVENT_OR_STAFF_NOT_VALID("PROD_007", "Event or staff is not valid", HttpStatus.BAD_REQUEST),
    DONATION_NOT_FOUND("PROD_008", "Donation not found", HttpStatus.NOT_FOUND),
    ACCESS_DENIED("PROD_009", "Access denied", HttpStatus.FORBIDDEN),
    DONATION_ITEM_STATUS_UPDATE_FAILED("PROD_010", "Failed to update donation item status", HttpStatus.INTERNAL_SERVER_ERROR);


    private final String code;
    private final String message;
    private final HttpStatus status;
}
