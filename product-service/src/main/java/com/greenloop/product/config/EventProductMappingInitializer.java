package com.greenloop.product.config;

import com.greenloop.product.entity.EventProductMapping;
import com.greenloop.product.entity.Product;
import com.greenloop.product.enums.EventMappingStatus;
import com.greenloop.product.repository.EventProductMappingRepository;
import com.greenloop.product.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class EventProductMappingInitializer implements CommandLineRunner {

    private final ProductRepository productRepository;
    private final EventProductMappingRepository eventProductMappingRepository;

    @Override
    public void run(String... args) {
        if (eventProductMappingRepository.count() == 0) {
            log.info("Initializing Event-Product mappings...");
            initializeEventProductMappings();
            log.info("Event-Product mapping initialization completed!");
        } else {
            log.info("Event-Product mappings already exist, skipping initialization");
        }
    }

    private void initializeEventProductMappings() {
        LocalDateTime now = LocalDateTime.now();

        // ✅ EVENT 1: Ngày hội Tái chế Xanh 2025 (ACTIVE NOW)
        // Thời gian: Đã bắt đầu từ 2 ngày trước, kéo dài 7 ngày
        assignProductsToEvent(
                1L,
                List.of("AT001", "AT002", "QJ001", "QJ002", "AK001"),
                now.minusDays(2),  // Bắt đầu từ 2 ngày trước
                now.plusDays(5),   // Kết thúc sau 5 ngày nữa
                EventMappingStatus.DISPLAYED
        );

        // ✅ EVENT 2: Chiến dịch Làm sạch Biển Vũng Tàu (ACTIVE NOW)
        // Thời gian: Đang diễn ra
        assignProductsToEvent(
                2L,
                List.of("AT003", "QS001", "QS003"),
                now.minusHours(12), // Bắt đầu từ 12 giờ trước
                now.plusDays(3),    // Kết thúc sau 3 ngày
                EventMappingStatus.DISPLAYED
        );

        // ✅ EVENT 5: Ngày Trái Đất Xanh 2025 (ACTIVE NOW - Event lớn)
        // Thời gian: Đang diễn ra, kéo dài
        assignProductsToEvent(
                5L,
                List.of("AT001", "AT003", "QJ002", "AK001", "AK002", "AK003", "DV001", "DV002"),
                now.minusDays(1),  // Bắt đầu từ hôm qua
                now.plusDays(10),  // Kết thúc sau 10 ngày
                EventMappingStatus.DISPLAYED
        );

        // ✅ EVENT 6: Workshop Làm Túi Vải từ Quần Áo Cũ (ACTIVE NOW)
        // Thời gian: Đang trong khung giờ workshop
        assignProductsToEvent(
                6L,
                List.of("AT002", "DV003", "QJ003"),
                now.minusHours(2),  // Bắt đầu từ 2 giờ trước
                now.plusHours(4),   // Kết thúc sau 4 giờ nữa
                EventMappingStatus.DISPLAYED
        );

        // ✅ EVENT 7: Trồng 1000 Cây Xanh cho Sài Gòn (ACTIVE NOW)
        // Thời gian: Đang trong ngày trồng cây
        assignProductsToEvent(
                7L,
                List.of("AT001", "QS002", "QS003", "QJ001"),
                now.minusHours(6),  // Bắt đầu từ 6 giờ trước (sáng sớm)
                now.plusHours(10),  // Kết thúc sau 10 giờ (chiều tối)
                EventMappingStatus.DISPLAYED
        );

        log.info("Total Event-Product mappings created: {}", eventProductMappingRepository.count());
    }

    private void assignProductsToEvent(
            Long eventId,
            List<String> productCodes,
            LocalDateTime displayFrom,
            LocalDateTime displayTo,
            EventMappingStatus status) {

        int successCount = 0;
        int skipCount = 0;

        for (String code : productCodes) {
            Product product = productRepository.findByCode(code).orElse(null);

            if (product == null) {
                log.warn("Product with code {} not found, skipping", code);
                skipCount++;
                continue;
            }

            boolean exists = eventProductMappingRepository
                    .existsByEventIdAndProductId(eventId, product.getId());

            if (exists) {
                log.debug("Mapping already exists for Event {} and Product {}", eventId, code);
                skipCount++;
                continue;
            }

            EventProductMapping mapping = EventProductMapping.builder()
                    .eventId(eventId)
                    .product(product)
                    .displayFrom(displayFrom)
                    .displayTo(displayTo)
                    .status(status)
                    .build();

            eventProductMappingRepository.save(mapping);
            successCount++;

            // ✅ Log chi tiết để dễ debug
            log.debug("Created mapping: Event {}, Product {} ({}), Display: {} to {}",
                    eventId, product.getId(), code, displayFrom, displayTo);
        }

        log.info("Event {}: Assigned {} products, Skipped {} products. " +
                        "Display period: {} to {}",
                eventId, successCount, skipCount, displayFrom, displayTo);
    }
}
