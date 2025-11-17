package com.greenloop.product.config;

import com.greenloop.product.entity.Category;
import com.greenloop.product.entity.Product;
import com.greenloop.product.entity.ProductAsset;
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

        // Áo thun
        createProductWithImages(
                "AT001",
                "Áo thun trắng basic",
                "Áo thun cotton 100%, form regular, màu trắng",
                aoThun,
                new BigDecimal("50000"),
                10,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                200, 30, 40, 1,  // Logistics: 200g, 30x40x1cm
                List.of(
                        "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=500",
                        "https://images.unsplash.com/photo-1618354691373-d851c5c3a990?w=500"
                )
        );

        createProductWithImages(
                "AT002",
                "Áo thun đen oversize",
                "Áo thun cotton form rộng, màu đen",
                aoThun,
                new BigDecimal("65000"),
                12,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                250, 35, 45, 1,
                List.of(
                        "https://images.unsplash.com/photo-1583743814966-8936f5b7be1a?w=500",
                        "https://images.unsplash.com/photo-1576566588028-4147f3842f27?w=500"
                )
        );

        createProductWithImages(
                "AT003",
                "Áo thun polo xanh navy",
                "Áo thun polo có cổ, màu xanh navy",
                aoThun,
                new BigDecimal("80000"),
                15,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.PURCHASE,
                220, 32, 42, 1,
                List.of(
                        "https://images.unsplash.com/photo-1586790170083-2f9ceadc732d?w=500"
                )
        );

        // Quần jean
        createProductWithImages(
                "QJ001",
                "Quần jean xanh đậm slim fit",
                "Quần jean dáng ôm, màu xanh đậm",
                quanJean,
                new BigDecimal("150000"),
                25,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                400, 40, 35, 2,  // 400g, 40x35x2cm
                List.of(
                        "https://images.unsplash.com/photo-1542272604-787c3835535d?w=500",
                        "https://images.unsplash.com/photo-1541099649105-f69ad21f3246?w=500"
                )
        );

        createProductWithImages(
                "QJ002",
                "Quần jean đen ống rộng",
                "Quần jean form rộng, màu đen",
                quanJean,
                new BigDecimal("180000"),
                30,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                450, 42, 38, 2,
                List.of(
                        "https://images.unsplash.com/photo-1582418702059-97ebafb35d09?w=500"
                )
        );

        createProductWithImages(
                "QJ003",
                "Quần jean rách xanh nhạt",
                "Quần jean rách gối, màu xanh nhạt",
                quanJean,
                new BigDecimal("120000"),
                20,
                ConditionGrade.FAIR,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                380, 40, 36, 2,
                List.of(
                        "https://images.unsplash.com/photo-1475178626620-a4d074967452?w=500"
                )
        );

        // Áo khoác
        createProductWithImages(
                "AK001",
                "Áo hoodie xám",
                "Áo hoodie nỉ bông, màu xám, có mũ",
                aoKhoac,
                new BigDecimal("200000"),
                35,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                500, 45, 50, 3,  // 500g, 45x50x3cm
                List.of(
                        "https://images.unsplash.com/photo-1556821840-3a63f95609a7?w=500",
                        "https://images.unsplash.com/photo-1578587018452-892bacefd3f2?w=500"
                )
        );

        createProductWithImages(
                "AK002",
                "Áo khoác denim xanh",
                "Áo khoác jean, màu xanh nhạt",
                aoKhoac,
                new BigDecimal("220000"),
                40,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.PURCHASE,
                600, 48, 52, 3,
                List.of(
                        "https://images.unsplash.com/photo-1551028719-00167b16eac5?w=500"
                )
        );

        createProductWithImages(
                "AK003",
                "Áo bomber đen",
                "Áo khoác bomber, màu đen, phong cách streetwear",
                aoKhoac,
                new BigDecimal("250000"),
                45,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                550, 46, 51, 3,
                List.of(
                        "https://images.unsplash.com/photo-1591047139829-d91aecb6caea?w=500"
                )
        );

        // Đầm váy
        createProductWithImages(
                "DV001",
                "Váy maxi hoa nhí",
                "Váy dài họa tiết hoa nhí, màu pastel",
                damVay,
                new BigDecimal("180000"),
                30,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                300, 40, 50, 2,  // 300g, 40x50x2cm
                List.of(
                        "https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=500",
                        "https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=500"
                )
        );

        createProductWithImages(
                "DV002",
                "Đầm suông trắng",
                "Đầm suông dáng A, màu trắng tinh khôi",
                damVay,
                new BigDecimal("150000"),
                25,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                280, 38, 48, 2,
                List.of(
                        "https://images.unsplash.com/photo-1566174053879-31528523f8ae?w=500"
                )
        );

        createProductWithImages(
                "DV003",
                "Váy jean ngắn",
                "Váy jean xanh nhạt, dáng ngắn trẻ trung",
                damVay,
                new BigDecimal("120000"),
                20,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                250, 35, 40, 1,
                List.of(
                        "https://images.unsplash.com/photo-1583496661160-fb5886a0aaaa?w=500"
                )
        );

        // Quần short
        createProductWithImages(
                "QS001",
                "Quần short kaki be",
                "Quần short kaki, màu be, phong cách casual",
                quanShort,
                new BigDecimal("80000"),
                15,
                ConditionGrade.GOOD,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                200, 30, 35, 1,  // 200g, 30x35x1cm
                List.of(
                        "https://images.unsplash.com/photo-1591195853828-11db59a44f6b?w=500"
                )
        );

        createProductWithImages(
                "QS002",
                "Quần short jean rách",
                "Quần short jean xanh nhạt, rách gấu",
                quanShort,
                new BigDecimal("90000"),
                18,
                ConditionGrade.FAIR,
                ProductStatus.AVAILABLE,
                ProductType.DONATION,
                220, 32, 36, 1,
                List.of(
                        "https://images.unsplash.com/photo-1591195851821-21b8d3b818ee?w=500"
                )
        );

        createProductWithImages(
                "QS003",
                "Quần short thể thao đen",
                "Quần short thể thao, màu đen, chất liệu thấm hút mồ hôi",
                quanShort,
                new BigDecimal("70000"),
                12,
                ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE,
                ProductType.PURCHASE,
                180, 28, 32, 1,
                List.of(
                        "https://images.unsplash.com/photo-1591195850639-4cebc8ec2d8b?w=500"
                )
        );

        log.info("Created 15 products with images and logistics info");
    }

    /**
     * Helper method để tạo product với images và logistics
     */
    private void createProductWithImages(
            String code,
            String name,
            String description,
            Category category,
            BigDecimal price,
            Integer ecoPointValue,
            ConditionGrade conditionGrade,
            ProductStatus status,
            ProductType type,
            int weight,
            int length,
            int width,
            int height,
            List<String> imageUrls) {

        Product product = Product.builder()
                .code(code)
                .name(name)
                .description(description)
                .category(category)
                .price(price)
                .ecoPointValue(ecoPointValue)
                .conditionGrade(conditionGrade)
                .status(status)
                .type(type)
                // Logistics info
                .weight(weight)
                .length(length)
                .width(width)
                .height(height)
                .build();

        // Add product assets
        for (int i = 0; i < imageUrls.size(); i++) {
            ProductAsset asset = ProductAsset.builder()
                    .mediaKey(code + "_" + (i + 1))
                    .imageUrl(imageUrls.get(i))
                    .product(product)
                    .build();

            product.getAssets().add(asset);
        }

        productRepository.save(product);

        log.info(" Created product: {} - {}g, {}x{}x{}cm, {} images",
                code, weight, length, width, height, imageUrls.size());
    }
}
