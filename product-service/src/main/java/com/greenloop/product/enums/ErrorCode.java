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
    DONATION_ITEM_STATUS_UPDATE_FAILED("PROD_010", "Failed to update donation item status", HttpStatus.INTERNAL_SERVER_ERROR),
    DONATION_ITEM_NOT_FOUND("PROD_011", "Donation item not found", HttpStatus.NOT_FOUND),
    PRODUCT_ASSET_NOT_FOUND("PROD_012", "Product asset not found", HttpStatus.NOT_FOUND),
    EVENT_NOT_FOUND("PROD_013", "Event not found", HttpStatus.NOT_FOUND),
    EVENT_PRODUCT_TIME_CONFLICT("PROD_014", "Event product display time conflict", HttpStatus.CONFLICT),
    EVENT_PRODUCT_MAPPING_NOT_FOUND("PROD_015", "Event product mapping not found", HttpStatus.NOT_FOUND),
    EVENT_PRODUCT_ALREADY_EXISTS("PROD_016", "Event product mapping already exists", HttpStatus.CONFLICT),
    PRODUCT_ALREADY_SOLD("PROD_017", "Product already sold", HttpStatus.CONFLICT),
    PRODUCT_NOT_AVAILABLE("PROD_018", "Product not available", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_IN_EVENT("PROD_019", "Product not assigned to this event", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_YET_DISPLAYABLE("PROD_020", "Product display time not yet started", HttpStatus.BAD_REQUEST),
    PRODUCT_DISPLAY_EXPIRED("PROD_021", "Product display time expired", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_DISPLAYED("PROD_022", "Product not in displayed status", HttpStatus.BAD_REQUEST);


    private final String code;
    private final String message;
    private final HttpStatus status;
}
