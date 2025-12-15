//package com.greenloop.product.worker;
//
//import com.greenloop.product.entity.EventProductMapping;
//import com.greenloop.product.enums.EventMappingStatus;
//import com.greenloop.product.repository.EventProductMappingRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.scheduling.annotation.Scheduled;
//import org.springframework.stereotype.Service;
//
//import java.time.LocalDateTime;
//import java.util.List;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class EventProductStatusScheduler {
//
//    private final EventProductMappingRepository mappingRepository;
//
//    @Scheduled(fixedRate = 60 * 60 * 1000)
//    public void updateAssignedToPrepare() {
//        LocalDateTime now = LocalDateTime.now();
//        LocalDateTime threshold = now.plusDays(1);
//        log.info("[Scheduler] Checking ASSIGNED -> PREPARE until {}", threshold);
//
//        List<EventProductMapping> mappings =
//                mappingRepository.findMappingsToPrepare(threshold);
//
//        log.info("Found {} mappings to update", mappings.size());
//
//        for (EventProductMapping m : mappings) {
//            m.setStatus(EventMappingStatus.PREPARED);
//        }
//
//        mappingRepository.saveAll(mappings);
//
//        log.info("[Scheduler] Updated {} mappings to PREPARE", mappings.size());
//    }
//}
