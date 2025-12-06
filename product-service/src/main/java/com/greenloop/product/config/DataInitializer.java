package com.greenloop.product.config;

import com.greenloop.product.entity.Category;
import com.greenloop.product.entity.Product;
import com.greenloop.product.entity.ProductAsset;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import com.greenloop.product.repository.CategoryRepository;
import com.greenloop.product.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class DataInitializer implements CommandLineRunner {

    private final CategoryRepository categoryRepository;
    private final ProductRepository productRepository;

    @Override
    public void run(String... args) {
        if (categoryRepository.count() == 0) {
            log.info("Initializing product data...");
            initializeCategories();
            initializeProducts();
            log.info("Product data initialization completed! Total: {} products", productRepository.count());
        } else {
            log.info("Product data already exists, skipping initialization");
        }
    }

    private void initializeCategories() {
        List<Category> categories = List.of(
                Category.builder()
                        .name("Áo thun")
                        .description("Áo thun nam, nữ các loại: áo thun trơn, áo thun polo, áo thun graphic")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Quần jean")
                        .description("Quần jean nam, nữ: slim fit, skinny, boyfriend, mom jeans, wide leg")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Áo khoác")
                        .description("Áo khoác, áo hoodie, áo jacket, áo bomber, áo denim")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Đầm váy")
                        .description("Đầm, váy nữ các loại: váy maxi, váy midi, váy ngắn, đầm suông")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Quần short")
                        .description("Quần short nam, nữ: short kaki, short jean, short thể thao")
                        .isActive(true)
                        .build(),
                Category.builder()
                        .name("Áo sơ mi")
                        .description("Áo sơ mi nam, nữ: sơ mi công sở, sơ mi flannel, sơ mi kẻ sọc")
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
        Category aoSoMi = categoryRepository.findByName("Áo sơ mi").orElseThrow();

        // ==================== ÁO THUN (10 sản phẩm) ====================

        createProductWithImages("AT001", "Áo Thun Trắng Basic Unisex",
                "Áo thun cotton 100%, form regular fit, cổ tròn, màu trắng tinh. Chất liệu thoáng mát, thấm hút mồ hôi tốt, phù hợp mọi lứa tuổi.",
                aoThun, new BigDecimal("45000"), 10, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 180, 28, 38, 1,
                List.of("https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=500",
                        "https://images.unsplash.com/photo-1618354691373-d851c5c3a990?w=500"));

        createProductWithImages("AT002", "Áo Thun Đen Oversize Streetwear",
                "Áo thun cotton form rộng, màu đen, phong cách streetwear. Thiết kế oversize trendy, mặc thoải mái.",
                aoThun, new BigDecimal("65000"), 15, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 250, 35, 45, 1,
                List.of("https://images.unsplash.com/photo-1583743814966-8936f5b7be1a?w=500",
                        "https://images.unsplash.com/photo-1576566588028-4147f3842f27?w=500"));

        createProductWithImages("AT003", "Áo Polo Navy Cao Cấp",
                "Áo thun polo có cổ, màu xanh navy, chất liệu cotton cao cấp. Phù hợp đi làm, đi chơi.",
                aoThun, new BigDecimal("85000"), 18, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 220, 32, 42, 1,
                List.of("https://images.unsplash.com/photo-1586790170083-2f9ceadc732d?w=500"));

        createProductWithImages("AT004", "Áo Thun Xám Melange V-Neck",
                "Áo thun cổ V, màu xám melange, chất liệu cotton pha spandex co giãn nhẹ. Form body thanh lịch.",
                aoThun, new BigDecimal("50000"), 12, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 190, 29, 39, 1,
                List.of("https://images.unsplash.com/photo-1562157873-818bc0726f68?w=500"));

        createProductWithImages("AT005", "Áo Thun Graphic NYC Vintage",
                "Áo thun in chữ NYC vintage, màu be, phong cách retro. Chất cotton mềm mại, bền màu.",
                aoThun, new BigDecimal("70000"), 16, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 200, 30, 40, 1,
                List.of("https://images.unsplash.com/photo-1503342217505-b0a15ec3261c?w=500"));

        createProductWithImages("AT006", "Áo Thun Hồng Pastel Nữ",
                "Áo thun nữ màu hồng pastel nhẹ nhàng, form fitted ôm dáng. Cotton co giãn thoải mái.",
                aoThun, new BigDecimal("55000"), 13, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 170, 27, 37, 1,
                List.of("https://images.unsplash.com/photo-1627225924765-552d49cf47ad?w=500"));

        createProductWithImages("AT007", "Áo Thun Sọc Ngang Navy White",
                "Áo thun sọc ngang màu navy trắng, phong cách nautical. Chất cotton mịn, form regular.",
                aoThun, new BigDecimal("60000"), 14, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 195, 29, 39, 1,
                List.of("https://images.unsplash.com/photo-1581655353564-df123a1eb820?w=500"));

        createProductWithImages("AT008", "Áo Polo Đỏ Đô Sang Trọng",
                "Áo polo màu đỏ đô, chất liệu pique cotton cao cấp. Phù hợp đi làm, đi chơi golf.",
                aoThun, new BigDecimal("90000"), 20, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 230, 32, 42, 1,
                List.of("https://images.unsplash.com/photo-1628015321067-7e592e235ca8?w=500"));

        createProductWithImages("AT009", "Áo Thun Xanh Lá Mint Fresh",
                "Áo thun màu xanh lá mint tươi mát, form regular unisex. Cotton thấm hút tốt.",
                aoThun, new BigDecimal("48000"), 11, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 185, 28, 38, 1,
                List.of("https://images.unsplash.com/photo-1622445275576-721325763afe?w=500"));

        createProductWithImages("AT010", "Áo Thun Cam Neon Statement",
                "Áo thun màu cam neon nổi bật, form oversize. Thích hợp cho các hoạt động ngoài trời.",
                aoThun, new BigDecimal("58000"), 13, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 205, 30, 40, 1,
                List.of("https://images.unsplash.com/photo-1529374255404-311a2a4f1fd9?w=500"));

        // ==================== QUẦN JEAN (10 sản phẩm) ====================

        createProductWithImages("QJ001", "Quần Jean Xanh Đậm Slim Fit Nam",
                "Quần jean dáng ôm slim fit, màu xanh đậm classic. Chất jean cotton co giãn nhẹ, thoải mái.",
                quanJean, new BigDecimal("150000"), 28, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 400, 40, 35, 2,
                List.of("https://images.unsplash.com/photo-1542272604-787c3835535d?w=500",
                        "https://images.unsplash.com/photo-1541099649105-f69ad21f3246?w=500"));

        createProductWithImages("QJ002", "Quần Jean Đen Ống Rộng Wide Leg",
                "Quần jean ống rộng màu đen, phong cách retro. Chất jean dày dặn bền đẹp.",
                quanJean, new BigDecimal("180000"), 32, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 450, 42, 38, 2,
                List.of("https://images.unsplash.com/photo-1582418702059-97ebafb35d09?w=500"));

        createProductWithImages("QJ003", "Quần Jean Rách Xanh Nhạt Distressed",
                "Quần jean rách gối màu xanh nhạt, phong cách grunge. Hiệu ứng rách tự nhiên.",
                quanJean, new BigDecimal("130000"), 24, ConditionGrade.FAIR,
                ProductStatus.AVAILABLE, ProductType.RESALE, 380, 40, 36, 2,
                List.of("https://images.unsplash.com/photo-1475178626620-a4d074967452?w=500"));

        createProductWithImages("QJ004", "Quần Jean Skinny Xám Nữ",
                "Quần jean skinny ôm sát màu xám, form dáng đẹp tôn dáng. Chất jean co giãn 4 chiều.",
                quanJean, new BigDecimal("140000"), 26, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 360, 38, 34, 2,
                List.of("https://images.unsplash.com/photo-1598522325074-042db73aa4e6?w=500"));

        createProductWithImages("QJ005", "Quần Jean Mom Jeans Xanh Vintage",
                "Quần jean mom jeans xanh vintage, eo cao. Phong cách retro thập niên 90s.",
                quanJean, new BigDecimal("165000"), 30, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 420, 41, 37, 2,
                List.of("https://images.unsplash.com/photo-1584370848010-d7fe6bc767ec?w=500"));

        createProductWithImages("QJ006", "Quần Jean Boyfriend Xanh Nhạt",
                "Quần jean boyfriend fit xanh nhạt, form rộng thoải mái. Phong cách casual trendy.",
                quanJean, new BigDecimal("155000"), 28, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 410, 40, 36, 2,
                List.of("https://images.unsplash.com/photo-1565084888279-aca607ecce0c?w=500"));

        createProductWithImages("QJ007", "Quần Jean Đen Rách Gấu Punk",
                "Quần jean đen rách gấu phong cách punk rock. Chất jean dày bền chắc.",
                quanJean, new BigDecimal("145000"), 26, ConditionGrade.FAIR,
                ProductStatus.AVAILABLE, ProductType.RESALE, 395, 40, 35, 2,
                List.of("https://images.unsplash.com/photo-1576995853123-5a10305d93c0?w=500"));

        createProductWithImages("QJ008", "Quần Jean Xanh Đen Straight Fit",
                "Quần jean ống đứng màu xanh đen, form straight fit cổ điển. Không bao giờ lỗi mốt.",
                quanJean, new BigDecimal("160000"), 29, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 430, 41, 37, 2,
                List.of("https://images.unsplash.com/photo-1604176354204-9268737828e4?w=500"));

        createProductWithImages("QJ009", "Quần Jean Trắng Off-White Nữ",
                "Quần jean màu trắng off-white, dáng slim fit. Tôn dáng, phù hợp mùa hè.",
                quanJean, new BigDecimal("135000"), 25, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 370, 39, 35, 2,
                List.of("https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?w=500"));

        createProductWithImages("QJ010", "Quần Jean Xanh Đậm Bootcut Retro",
                "Quần jean ống loe bootcut màu xanh đậm, phong cách retro 70s. Form dáng cổ điển.",
                quanJean, new BigDecimal("170000"), 31, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 440, 41, 37, 2,
                List.of("https://images.unsplash.com/photo-1582552938357-32b906df40cb?w=500"));

        // ==================== ÁO KHOÁC (10 sản phẩm) ====================

        createProductWithImages("AK001", "Áo Hoodie Xám Melange Classic",
                "Áo hoodie nỉ bông màu xám melange, có mũ và túi kangaroo. Ấm áp, thoải mái.",
                aoKhoac, new BigDecimal("200000"), 38, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 500, 45, 50, 3,
                List.of("https://images.unsplash.com/photo-1556821840-3a63f95609a7?w=500",
                        "https://images.unsplash.com/photo-1578587018452-892bacefd3f2?w=500"));

        createProductWithImages("AK002", "Áo Khoác Denim Xanh Vintage",
                "Áo khoác jean màu xanh nhạt, phong cách vintage. Chất denim dày dặn bền đẹp.",
                aoKhoac, new BigDecimal("220000"), 42, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 600, 48, 52, 3,
                List.of("https://images.unsplash.com/photo-1551028719-00167b16eac5?w=500"));

        createProductWithImages("AK003", "Áo Bomber Đen Streetwear",
                "Áo khoác bomber màu đen, phong cách streetwear. Chất liệu polyester nhẹ, chống gió.",
                aoKhoac, new BigDecimal("250000"), 48, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 550, 46, 51, 3,
                List.of("https://images.unsplash.com/photo-1591047139829-d91aecb6caea?w=500"));

        createProductWithImages("AK004", "Áo Hoodie Đỏ Supreme Style",
                "Áo hoodie màu đỏ, phong cách Supreme. Nỉ bông dày, ấm áp mùa đông.",
                aoKhoac, new BigDecimal("280000"), 52, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 520, 45, 50, 3,
                List.of("https://images.unsplash.com/photo-1620799140408-edc6dcb6d633?w=500"));

        createProductWithImages("AK005", "Áo Khoác Gió Xanh Navy",
                "Áo khoác gió màu xanh navy, chống nước nhẹ. Phù hợp mùa mưa, thể thao.",
                aoKhoac, new BigDecimal("190000"), 36, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 480, 44, 49, 3,
                List.of("https://images.unsplash.com/photo-1544441892-794166f1e3be?w=500"));

        createProductWithImages("AK006", "Áo Khoác Da Đen Biker Style",
                "Áo khoác da giả màu đen, phong cách biker. Thiết kế khóa kéo cá tính.",
                aoKhoac, new BigDecimal("320000"), 60, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 650, 49, 53, 3,
                List.of("https://images.unsplash.com/photo-1551028719-00167b16eac5?w=500"));

        createProductWithImages("AK007", "Áo Hoodie Zip Xanh Lá",
                "Áo hoodie có khóa kéo màu xanh lá, túi hai bên. Chất nỉ cotton mềm mại.",
                aoKhoac, new BigDecimal("210000"), 40, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 510, 45, 50, 3,
                List.of("https://images.unsplash.com/photo-1620799139834-6b8f844fbe29?w=500"));

        createProductWithImages("AK008", "Áo Khoác Nỉ Bomber Cam",
                "Áo bomber nỉ màu cam, tay bo chun. Phong cách sporty năng động.",
                aoKhoac, new BigDecimal("230000"), 44, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 530, 46, 51, 3,
                List.of("https://images.unsplash.com/photo-1608228088098-f5a2b6ce2fc9?w=500"));

        createProductWithImages("AK009", "Áo Khoác Parka Xanh Rêu",
                "Áo khoác parka dài màu xanh rêu, có mũ lông. Ấm áp mùa đông.",
                aoKhoac, new BigDecimal("350000"), 65, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 700, 50, 55, 4,
                List.of("https://images.unsplash.com/photo-1539533018447-63fcce2678e3?w=500"));

        createProductWithImages("AK010", "Áo Khoác Bomber MA-1 Đen",
                "Áo bomber MA-1 màu đen classic, túi tay và túi zip. Phong cách quân đội.",
                aoKhoac, new BigDecimal("290000"), 55, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 580, 47, 52, 3,
                List.of("https://images.unsplash.com/photo-1591047139829-d91aecb6caea?w=500"));

        // ==================== ĐẦM VÁY (10 sản phẩm) ====================

        createProductWithImages("DV001", "Váy Maxi Hoa Nhí Pastel",
                "Váy dài maxi họa tiết hoa nhí màu pastel. Chất vải voan mỏng nhẹ, thích hợp dạo biển.",
                damVay, new BigDecimal("180000"), 34, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 300, 40, 50, 2,
                List.of("https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=500",
                        "https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=500"));

        createProductWithImages("DV002", "Đầm Suông Trắng Công Sở",
                "Đầm suông dáng A màu trắng tinh khôi. Thiết kế thanh lịch, phù hợp đi làm.",
                damVay, new BigDecimal("150000"), 28, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 280, 38, 48, 2,
                List.of("https://images.unsplash.com/photo-1566174053879-31528523f8ae?w=500"));

        createProductWithImages("DV003", "Váy Jean Ngắn Xanh Nhạt",
                "Váy jean xanh nhạt dáng ngắn, phong cách trẻ trung. Chất jean mềm, thoải mái.",
                damVay, new BigDecimal("120000"), 22, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 250, 35, 40, 1,
                List.of("https://images.unsplash.com/photo-1583496661160-fb5886a0aaaa?w=500"));

        createProductWithImages("DV004", "Đầm Xòe Đen Dự Tiệc",
                "Đầm xòe màu đen, cổ tròn, tay ngắn. Thích hợp dự tiệc, sự kiện trang trọng.",
                damVay, new BigDecimal("200000"), 38, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 320, 40, 50, 2,
                List.of("https://images.unsplash.com/photo-1539008835657-9e8e9680c956?w=500"));

        createProductWithImages("DV005", "Váy Midi Kẻ Sọc Navy",
                "Váy midi kẻ sọc ngang màu navy trắng, dáng chữ A. Phong cách nautical thanh lịch.",
                damVay, new BigDecimal("165000"), 31, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 290, 38, 48, 2,
                List.of("https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=500"));

        createProductWithImages("DV006", "Đầm Babydoll Hồng Pastel",
                "Đầm babydoll màu hồng pastel, dáng xòe nhẹ nhàng. Phong cách tiểu thư ngọt ngào.",
                damVay, new BigDecimal("145000"), 27, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 270, 37, 47, 2,
                List.of("https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=500"));

        createProductWithImages("DV007", "Váy Bút Chì Đen Công Sở",
                "Váy bút chì màu đen, ôm body tôn dáng. Thích hợp văn phòng, công sở.",
                damVay, new BigDecimal("135000"), 25, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 260, 36, 45, 1,
                List.of("https://images.unsplash.com/photo-1583496661160-fb5886a0aaaa?w=500"));

        createProductWithImages("DV008", "Đầm Maxi Đỏ Dự Tiệc",
                "Đầm maxi màu đỏ dài chạm sàn, vai bẹt quyến rũ. Thích hợp dự tiệc cưới, sự kiện.",
                damVay, new BigDecimal("250000"), 48, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 350, 42, 52, 2,
                List.of("https://images.unsplash.com/photo-1566174053879-31528523f8ae?w=500"));

        createProductWithImages("DV009", "Váy Hoa Vintage Boho Style",
                "Váy hoa vintage phong cách boho, màu sắc tươi sáng. Chất vải cotton thoáng mát.",
                damVay, new BigDecimal("155000"), 29, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 285, 38, 48, 2,
                List.of("https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=500"));

        createProductWithImages("DV010", "Đầm Suông Xanh Mint Mùa Hè",
                "Đầm suông màu xanh mint tươi mát, tay ngắn. Chất vải linen mềm mại, mát mẻ.",
                damVay, new BigDecimal("140000"), 26, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 275, 38, 47, 2,
                List.of("https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=500"));

        // ==================== QUẦN SHORT (10 sản phẩm) ====================

        createProductWithImages("QS001", "Quần Short Kaki Be Casual",
                "Quần short kaki màu be, phong cách casual thoải mái. Chất kaki cotton bền đẹp.",
                quanShort, new BigDecimal("80000"), 16, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 200, 30, 35, 1,
                List.of("https://images.unsplash.com/photo-1591195853828-11db59a44f6b?w=500"));

        createProductWithImages("QS002", "Quần Short Jean Rách Xanh",
                "Quần short jean xanh nhạt rách gấu, phong cách grunge. Chất jean mềm thoải mái.",
                quanShort, new BigDecimal("90000"), 18, ConditionGrade.FAIR,
                ProductStatus.AVAILABLE, ProductType.RESALE, 220, 32, 36, 1,
                List.of("https://images.unsplash.com/photo-1591195851821-21b8d3b818ee?w=500"));

        createProductWithImages("QS003", "Quần Short Thể Thao Đen",
                "Quần short thể thao màu đen, chất liệu polyester thấm hút mồ hôi. Phù hợp tập gym.",
                quanShort, new BigDecimal("70000"), 14, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 180, 28, 32, 1,
                List.of("https://images.unsplash.com/photo-1591195850639-4cebc8ec2d8b?w=500"));

        createProductWithImages("QS004", "Quần Short Cargo Xanh Rêu",
                "Quần short cargo màu xanh rêu, nhiều túi tiện lợi. Phong cách military.",
                quanShort, new BigDecimal("95000"), 19, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 240, 32, 36, 1,
                List.of("https://images.unsplash.com/photo-1591195853828-11db59a44f6b?w=500"));

        createProductWithImages("QS005", "Quần Short Jean Đen Skinny",
                "Quần short jean đen dáng ôm skinny, tôn dáng. Chất jean co giãn thoải mái.",
                quanShort, new BigDecimal("85000"), 17, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 210, 31, 35, 1,
                List.of("https://images.unsplash.com/photo-1591195851821-21b8d3b818ee?w=500"));

        createProductWithImages("QS006", "Quần Short Kaki Xám Túi Hộp",
                "Quần short kaki xám, có túi hộp hai bên. Phong cách streetwear năng động.",
                quanShort, new BigDecimal("88000"), 17, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 215, 31, 35, 1,
                List.of("https://images.unsplash.com/photo-1591195853828-11db59a44f6b?w=500"));

        createProductWithImages("QS007", "Quần Short Thể Thao Xanh Dương",
                "Quần short thể thao màu xanh dương, sọc trắng hai bên. Chất polyester nhẹ.",
                quanShort, new BigDecimal("75000"), 15, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 190, 29, 33, 1,
                List.of("https://images.unsplash.com/photo-1591195850639-4cebc8ec2d8b?w=500"));

        createProductWithImages("QS008", "Quần Short Jean Xanh Đậm Classic",
                "Quần short jean xanh đậm classic, không rách. Form regular fit thoải mái.",
                quanShort, new BigDecimal("92000"), 18, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 225, 32, 36, 1,
                List.of("https://images.unsplash.com/photo-1591195851821-21b8d3b818ee?w=500"));

        createProductWithImages("QS009", "Quần Short Kaki Nâu Vintage",
                "Quần short kaki màu nâu vintage, phong cách retro. Chất kaki dày bền chắc.",
                quanShort, new BigDecimal("82000"), 16, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 205, 30, 35, 1,
                List.of("https://images.unsplash.com/photo-1591195853828-11db59a44f6b?w=500"));

        createProductWithImages("QS010", "Quần Short Thể Thao Xám Melange",
                "Quần short thể thao xám melange, bo chun thoải mái. Phù hợp chạy bộ, tập luyện.",
                quanShort, new BigDecimal("68000"), 13, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 175, 28, 32, 1,
                List.of("https://images.unsplash.com/photo-1591195850639-4cebc8ec2d8b?w=500"));

        // ==================== ÁO SƠ MI (10 sản phẩm) ====================

        createProductWithImages("SM001", "Áo Sơ Mi Trắng Công Sở",
                "Áo sơ mi trắng trơn tay dài, cổ bẻ classic. Chất cotton cao cấp, phù hợp văn phòng.",
                aoSoMi, new BigDecimal("110000"), 22, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 240, 34, 44, 1,
                List.of("https://images.unsplash.com/photo-1602810318383-e386cc2a3ccf?w=500"));

        createProductWithImages("SM002", "Áo Sơ Mi Xanh Navy Dáng Slim",
                "Áo sơ mi xanh navy dáng slim fit ôm body. Thiết kế thanh lịch, sang trọng.",
                aoSoMi, new BigDecimal("120000"), 24, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 250, 35, 45, 1,
                List.of("https://images.unsplash.com/photo-1620012253295-c15cc3e65df4?w=500"));

        createProductWithImages("SM003", "Áo Sơ Mi Flannel Kẻ Sọc Đỏ",
                "Áo sơ mi flannel kẻ sọc đỏ đen, phong cách lumberjack. Chất flannel cotton ấm áp.",
                aoSoMi, new BigDecimal("95000"), 19, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 280, 36, 46, 1,
                List.of("https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=500"));

        createProductWithImages("SM004", "Áo Sơ Mi Hồng Nữ Công Sở",
                "Áo sơ mi nữ màu hồng pastel, tay dài. Thiết kế nữ tính, thanh lịch.",
                aoSoMi, new BigDecimal("105000"), 21, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 230, 33, 43, 1,
                List.of("https://images.unsplash.com/photo-1598032895397-b9372f6ddfe6?w=500"));

        createProductWithImages("SM005", "Áo Sơ Mi Jean Xanh Nhạt",
                "Áo sơ mi jean màu xanh nhạt, phong cách casual. Chất denim mềm thoải mái.",
                aoSoMi, new BigDecimal("130000"), 26, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 290, 36, 46, 1,
                List.of("https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=500"));

        createProductWithImages("SM006", "Áo Sơ Mi Lụa Đen Sang Trọng",
                "Áo sơ mi lụa màu đen, bóng mượt sang trọng. Phù hợp dự tiệc, sự kiện.",
                aoSoMi, new BigDecimal("150000"), 28, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 210, 33, 43, 1,
                List.of("https://images.unsplash.com/photo-1598032895397-b9372f6ddfe6?w=500"));

        createProductWithImages("SM007", "Áo Sơ Mi Flannel Xanh Kẻ",
                "Áo sơ mi flannel kẻ xanh xám, phong cách outdoor. Chất flannel dày ấm.",
                aoSoMi, new BigDecimal("100000"), 20, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 275, 36, 46, 1,
                List.of("https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=500"));

        createProductWithImages("SM008", "Áo Sơ Mi Xanh Mint Nữ",
                "Áo sơ mi nữ màu xanh mint tươi mát, tay ngắn. Phong cách trẻ trung, năng động.",
                aoSoMi, new BigDecimal("98000"), 19, ConditionGrade.LIKE_NEW,
                ProductStatus.AVAILABLE, ProductType.RESALE, 220, 33, 43, 1,
                List.of("https://images.unsplash.com/photo-1598032895397-b9372f6ddfe6?w=500"));

        createProductWithImages("SM009", "Áo Sơ Mi Kaki Be Túi Hộp",
                "Áo sơ mi kaki màu be, có túi hộp hai bên ngực. Phong cách military casual.",
                aoSoMi, new BigDecimal("115000"), 23, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 260, 35, 45, 1,
                List.of("https://images.unsplash.com/photo-1602810318383-e386cc2a3ccf?w=500"));

        createProductWithImages("SM010", "Áo Sơ Mi Hoa Văn Hawaii",
                "Áo sơ mi hoa văn Hawaii tay ngắn, màu sắc tươi sáng. Phong cách resort nghỉ dưỡng.",
                aoSoMi, new BigDecimal("108000"), 21, ConditionGrade.GOOD,
                ProductStatus.AVAILABLE, ProductType.RESALE, 235, 34, 44, 1,
                List.of("https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=500"));

        log.info("Created 50 products successfully!");
    }

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
                .weight(weight)
                .length(length)
                .width(width)
                .height(height)
                .build();

        for (int i = 0; i < imageUrls.size(); i++) {
            ProductAsset asset = ProductAsset.builder()
                    .mediaKey(code + "_IMG_" + (i + 1))
                    .imageUrl(imageUrls.get(i))
                    .product(product)
                    .build();

            product.getAssets().add(asset);
        }

        productRepository.save(product);
    }
}
