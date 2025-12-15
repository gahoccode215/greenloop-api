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
import java.util.ArrayList;
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
            log.info("Event-Product mapping initialization completed! Total: {}",
                    eventProductMappingRepository.count());
        } else {
            log.info("Event-Product mappings already exist, skipping initialization");
        }
    }

    private void initializeEventProductMappings() {
        LocalDateTime now = LocalDateTime.now();

        // EVENT 1: Ngày Hội Thu Gom Quần Áo Cũ Quận 1 (ONGOING)
        // Status: DISPLAYED (đang trưng bày tại sự kiện, đang diễn ra)
        // Products: ID 1-5 (AT001-AT005)
        assignProductsToEventByIds(
                1L,
                List.of(1L, 2L, 3L, 4L, 5L),
                now.minusDays(1),
                now.plusDays(2),
                EventMappingStatus.DISPLAYED
        );

        // EVENT 2: Thu Gom Cuối Tuần - Gò Vấp (UPCOMING)
        // Status: PREPARED (đã chuẩn bị sẵn, chờ sự kiện bắt đầu)
        // Products: ID 6-10 (AT006-AT010)
        assignProductsToEventByIds(
                2L,
                List.of(6L, 7L, 8L, 9L, 10L),
                now.plusDays(7),
                now.plusDays(8),
                EventMappingStatus.PREPARED
        );

        // EVENT 3: Thu Gom Tháng 11 - Quận 3 (CLOSED)
        // Status: CLOSED - KHÔNG GÁN PRODUCT

        // EVENT 4: Thu Gom Quận 7 - Tạm Hoãn (CANCELED)
        // Status: CANCELED - KHÔNG GÁN PRODUCT

        // EVENT 5: Đại Hội Toàn Thành Phố 2025 (UPCOMING - Event lớn)
        // Status: ASSIGNED (đã phân công, chưa chuẩn bị)
        // Products: ID 11-20 (QJ001-QJ010)
        assignProductsToEventByIds(
                5L,
                List.of(11L, 12L, 13L, 14L, 15L, 16L, 17L, 18L, 19L, 20L),
                now.plusDays(30),
                now.plusDays(31),
                EventMappingStatus.ASSIGNED
        );

        // EVENT 6: Thu Gom Tháng 12 - Bình Thạnh (UPCOMING)
        // Status: PREPARED (đã chuẩn bị sẵn, sắp diễn ra)
        // Products: ID 21-28 (AK001-AK008)
        assignProductsToEventByIds(
                6L,
                List.of(21L, 22L, 23L, 24L, 25L, 26L, 27L, 28L),
                now.plusDays(5),
                now.plusDays(5).plusHours(4),
                EventMappingStatus.PREPARED
        );

        // EVENT 7: Thu Gom Phú Mỹ Hưng (UPCOMING)
        // Status: ASSIGNED (đã phân công, chưa chuẩn bị chi tiết)
        // Products: ID 29-35 (AK009, AK010, DV001-DV005)
        assignProductsToEventByIds(
                7L,
                List.of(29L, 30L, 31L, 32L, 33L, 34L, 35L),
                now.plusDays(20),
                now.plusDays(20).plusHours(6),
                EventMappingStatus.ASSIGNED
        );

        log.info("Successfully created mappings for active/upcoming events only");
    }

    /**
     * Gán products cho event theo danh sách Product IDs
     */
    private void assignProductsToEventByIds(
            Long eventId,
            List<Long> productIds,
            LocalDateTime displayFrom,
            LocalDateTime displayTo,
            EventMappingStatus status) {

        List<EventProductMapping> mappings = new ArrayList<>();
        int successCount = 0;
        int notFoundCount = 0;

        for (Long productId : productIds) {
            Product product = productRepository.findById(productId).orElse(null);

            if (product == null) {
                log.warn("Product ID {} not found, skipping", productId);
                notFoundCount++;
                continue;
            }

            // Check if mapping already exists
            boolean exists = eventProductMappingRepository
                    .existsByEventIdAndProductId(eventId, product.getId());

            if (exists) {
                log.debug("Mapping already exists for Event {} and Product ID {}", eventId, productId);
                continue;
            }

            EventProductMapping mapping = EventProductMapping.builder()
                    .eventId(eventId)
                    .product(product)
                    .displayFrom(displayFrom)
                    .displayTo(displayTo)
                    .status(status)
                    .build();

            mappings.add(mapping);
            successCount++;
        }

        if (!mappings.isEmpty()) {
            eventProductMappingRepository.saveAll(mappings);
        }

        log.info("Event {}: Assigned {} products (IDs: {}), Not found: {}, Status: {}, Display: {} to {}",
                eventId,
                successCount,
                productIds,
                notFoundCount,
                status,
                displayFrom,
                displayTo);
    }
}
