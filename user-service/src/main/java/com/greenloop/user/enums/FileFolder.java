package com.greenloop.user.enums;

import lombok.Getter;
import lombok.Setter;

@Getter
public enum FileFolder {
    EMPLOYEE_IMAGE("employees"),
    CUSTOMER_IMAGE("customers"),
    PRODUCT_IMAGE("products"),
    CATEGORY_IMAGE("categories"),
    DOCUMENT("documents");

    private final String path;

    FileFolder(String path) {
        this.path = path;
    }

}
