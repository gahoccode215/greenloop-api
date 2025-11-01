package com.greenloop.product.config;

import com.greenloop.product.entity.Category;
import com.greenloop.product.entity.Product;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import com.greenloop.product.repository.CategoryRepository;
import com.greenloop.product.repository.ProductRepository;
import java.math.BigDecimal;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final CategoryRepository categoryRepository;
    private final ProductRepository productRepository;

    @Override
    public void run(String... args) {
        if (categoryRepository.count() == 0) {
            log.info("Initializing data...");
            initializeCategories();
            initializeProducts();
            log.info("Data initialization completed!");
        } else {
            log.info("Data already exists, skipping initialization");
        }
    }

    private void initializeCategories() {
        List<Category> categories = List.of(
                Category.builder()
                        .name("Áo thun")
                        .description("Áo thun nam, nữ các loại")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Quần jean")
                        .description("Quần jean nam, nữ các loại")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Áo khoác")
                        .description("Áo khoác, áo hoodie, áo jacket")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Đầm váy")
                        .description("Đầm, váy nữ các loại")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Quần short")
                        .description("Quần short nam, nữ các loại")
                        .isActive(true)
                        .build()
        );

        categoryRepository.saveAll(categories);
        log.info("Created {} categories", categories.size());
    }

    private void initializeProducts() {
        Category aoThun = categoryRepository.findByName("Áo thun").orElseThrow();
        Category quanJean = categoryRepository.findByName("Quần jean").orElseThrow();
        Category aoKhoac = categoryRepository.findByName("Áo khoác").orElseThrow();
        Category damVay = categoryRepository.findByName("Đầm váy").orElseThrow();
        Category quanShort = categoryRepository.findByName("Quần short").orElseThrow();

        List<Product> products = List.of(
                // Áo thun (3 sản phẩm)
                Product.builder()
                        .code("AT001")
                        .name("Áo thun trắng basic")
                        .description("Áo thun cotton 100%, form regular, màu trắng")
                        .category(aoThun)
                        .price(new BigDecimal("50000"))
                        .ecoPointValue(10)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("AT002")
                        .name("Áo thun đen oversize")
                        .description("Áo thun cotton form rộng, màu đen")
                        .category(aoThun)
                        .price(new BigDecimal("65000"))
                        .ecoPointValue(12)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("AT003")
                        .name("Áo thun polo xanh navy")
                        .description("Áo thun polo có cổ, màu xanh navy")
                        .category(aoThun)
                        .price(new BigDecimal("80000"))
                        .ecoPointValue(15)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.PURCHASE)
                        .isActive(true)
                        .build(),

                // Quần jean (3 sản phẩm)
                Product.builder()
                        .code("QJ001")
                        .name("Quần jean xanh đậm slim fit")
                        .description("Quần jean dáng ôm, màu xanh đậm")
                        .category(quanJean)
                        .price(new BigDecimal("150000"))
                        .ecoPointValue(25)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("QJ002")
                        .name("Quần jean đen ống rộng")
                        .description("Quần jean form rộng, màu đen")
                        .category(quanJean)
                        .price(new BigDecimal("180000"))
                        .ecoPointValue(30)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("QJ003")
                        .name("Quần jean rách xanh nhạt")
                        .description("Quần jean rách gối, màu xanh nhạt")
                        .category(quanJean)
                        .price(new BigDecimal("120000"))
                        .ecoPointValue(20)
                        .conditionGrade(ConditionGrade.FAIR)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),

                // Áo khoác (3 sản phẩm)
                Product.builder()
                        .code("AK001")
                        .name("Áo hoodie xám")
                        .description("Áo hoodie nỉ bông, màu xám, có mũ")
                        .category(aoKhoac)
                        .price(new BigDecimal("200000"))
                        .ecoPointValue(35)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("AK002")
                        .name("Áo khoác denim xanh")
                        .description("Áo khoác jean, màu xanh nhạt")
                        .category(aoKhoac)
                        .price(new BigDecimal("220000"))
                        .ecoPointValue(40)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.PURCHASE)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("AK003")
                        .name("Áo bomber đen")
                        .description("Áo khoác bomber, màu đen, phong cách streetwear")
                        .category(aoKhoac)
                        .price(new BigDecimal("250000"))
                        .ecoPointValue(45)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),

                // Đầm váy (3 sản phẩm)
                Product.builder()
                        .code("DV001")
                        .name("Váy maxi hoa nhí")
                        .description("Váy dài họa tiết hoa nhí, màu pastel")
                        .category(damVay)
                        .price(new BigDecimal("180000"))
                        .ecoPointValue(30)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("DV002")
                        .name("Đầm suông trắng")
                        .description("Đầm suông dáng A, màu trắng tinh khôi")
                        .category(damVay)
                        .price(new BigDecimal("150000"))
                        .ecoPointValue(25)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("DV003")
                        .name("Váy jean ngắn")
                        .description("Váy jean xanh nhạt, dáng ngắn trẻ trung")
                        .category(damVay)
                        .price(new BigDecimal("120000"))
                        .ecoPointValue(20)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),

                // Quần short (3 sản phẩm)
                Product.builder()
                        .code("QS001")
                        .name("Quần short kaki be")
                        .description("Quần short kaki, màu be, phong cách casual")
                        .category(quanShort)
                        .price(new BigDecimal("80000"))
                        .ecoPointValue(15)
                        .conditionGrade(ConditionGrade.GOOD)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("QS002")
                        .name("Quần short jean rách")
                        .description("Quần short jean xanh nhạt, rách gấu")
                        .category(quanShort)
                        .price(new BigDecimal("90000"))
                        .ecoPointValue(18)
                        .conditionGrade(ConditionGrade.FAIR)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.DONATION)
                        .isActive(true)
                        .build(),
                Product.builder()
                        .code("QS003")
                        .name("Quần short thể thao đen")
                        .description("Quần short thể thao, màu đen, chất liệu thấm hút mồ hôi")
                        .category(quanShort)
                        .price(new BigDecimal("70000"))
                        .ecoPointValue(12)
                        .conditionGrade(ConditionGrade.LIKE_NEW)
                        .status(ProductStatus.AVAILABLE)
                        .type(ProductType.PURCHASE)
                        .isActive(true)
                        .build()
        );

        List<Product> savedProducts = productRepository.saveAll(products);
        log.info("Created {} products", savedProducts.size());
    }
}
