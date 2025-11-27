package com.greenloop.event.config;

import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventMedia;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.repository.EventMediaRepository;
import com.greenloop.event.repository.EventRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInit implements CommandLineRunner {

  private final EventRepository eventRepository;
  private final EventMediaRepository eventMediaRepository;

  @Override
  @Transactional
  public void run(String... args) {
    if (eventRepository.count() > 0) {
      log.info("Events already initialized. Skipping data initialization.");
      return;
    }

    log.info("Starting event data initialization...");
    initializeEvents();
    log.info("Event data initialization completed successfully.");
  }

  private void initializeEvents() {
    // Event 1: Sự kiện đang diễn ra
    Event event1 =
        Event.builder()
            .code("EVT001")
            .name("Ngày hội Tái chế Xanh 2025")
            .description(
                "Sự kiện tái chế lớn nhất năm với nhiều hoạt động thú vị: thu gom rác thải, tái chế giấy, nhựa, kim loại. Cùng nhau xây dựng môi trường xanh, sạch, đẹp cho cộng đồng.")
            .startTime(LocalDateTime.now().minusDays(1))
            .endTime(LocalDateTime.now().plusDays(2))
            .imageUrl("https://images.unsplash.com/photo-1532996122724-e3c354a0b15b")
            .mediaKey("recycle_event_001")
            .locationDetail("Công viên Tao Đàn, Quận 1, TP.HCM")
            .latitude("10.7829")
            .longitude("106.6933")
            .status(EventStatus.ONGOING)
            .note("Mang theo túi vải và găng tay")
            .build();
    event1.setCreatedBy(1L);
    event1.setUpdatedBy(1L);
    event1 = eventRepository.save(event1);

    addEventMedia(
        event1,
        List.of(
            "https://images.unsplash.com/photo-1611284446314-60a58ac0deb9",
            "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09",
            "https://images.unsplash.com/photo-1532996122724-e3c354a0b15b"));

    // Event 2: Sự kiện sắp tới
    Event event2 =
        Event.builder()
            .code("EVT002")
            .name("Chiến dịch Làm sạch Biển Vũng Tàu")
            .description(
                "Cùng nhau làm sạch bãi biển, bảo vệ đại dương. Thu gom rác thải nhựa, tổ chức các hoạt động giáo dục về bảo vệ môi trường biển.")
            .startTime(LocalDateTime.now().plusDays(7))
            .endTime(LocalDateTime.now().plusDays(8))
            .imageUrl("https://images.unsplash.com/photo-1559827260-dc66d52bef19")
            .mediaKey("beach_cleanup_002")
            .locationDetail("Bãi biển Bãi Sau, Vũng Tàu")
            .latitude("10.3454")
            .longitude("107.0845")
            .status(EventStatus.UPCOMING)
            .note("Xe bus đưa đón tại Bến xe Miền Đông lúc 5h sáng")
            .build();
    event2.setCreatedBy(1L);
    event2.setUpdatedBy(1L);
    event2 = eventRepository.save(event2);

    addEventMedia(
        event2,
        List.of(
            "https://images.unsplash.com/photo-1621451537084-482c73073a0f",
            "https://images.unsplash.com/photo-1618477461853-cf6ed80faba5"));

    // Event 3: Sự kiện đã kết thúc
    Event event3 =
        Event.builder()
            .code("EVT003")
            .name("Hội chợ Đồ Cũ Tái Chế")
            .description(
                "Mua bán, trao đổi đồ cũ. Góp phần giảm thiểu rác thải, khuyến khích lối sống tiết kiệm, bảo vệ môi trường.")
            .startTime(LocalDateTime.now().minusDays(10))
            .endTime(LocalDateTime.now().minusDays(8))
            .imageUrl("https://images.unsplash.com/photo-1604719312566-8912e9227c6a")
            .mediaKey("secondhand_market_003")
            .locationDetail("Nhà Văn hóa Thanh Niên, Quận 3, TP.HCM")
            .latitude("10.7756")
            .longitude("106.6917")
            .status(EventStatus.CLOSED)
            .note("Sự kiện thành công vượt mong đợi")
            .build();
    event3.setCreatedBy(1L);
    event3.setUpdatedBy(1L);
    event3 = eventRepository.save(event3);

    addEventMedia(
        event3,
        List.of(
            "https://images.unsplash.com/photo-1543269865-cbf427effbad",
            "https://images.unsplash.com/photo-1540221652346-e5dd6b50f3e7",
            "https://images.unsplash.com/photo-1441986300917-64674bd600d8"));

    // Event 4: Sự kiện bị hủy
    Event event4 =
        Event.builder()
            .code("EVT004")
            .name("Workshop Tái chế Đồ Thủ công")
            .description("Học cách tái chế giấy, nhựa thành các sản phẩm thủ công mỹ nghệ độc đáo.")
            .startTime(LocalDateTime.now().plusDays(14))
            .endTime(LocalDateTime.now().plusDays(14).plusHours(4))
            .imageUrl("https://images.unsplash.com/photo-1452860606245-08befc0ff44b")
            .mediaKey("workshop_004")
            .locationDetail("Trung tâm Văn hóa Quận 7, TP.HCM")
            .latitude("10.7321")
            .longitude("106.7196")
            .status(EventStatus.CANCELED)
            .note("Hủy do không đủ số lượng đăng ký")
            .build();
    event4.setCreatedBy(1L);
    event4.setUpdatedBy(1L);
    event4 = eventRepository.save(event4);

    addEventMedia(event4, List.of("https://images.unsplash.com/photo-1509099836639-18ba1795216d"));

    // Event 5: Sự kiện lớn sắp tới
    Event event5 =
        Event.builder()
            .code("EVT005")
            .name("Ngày Trái Đất Xanh 2025")
            .description(
                "Sự kiện lớn nhất năm với hàng nghìn người tham gia. Các hoạt động: trồng cây, tái chế rác thải, triển lãm công nghệ xanh, tọa đàm về biến đổi khí hậu.")
            .startTime(LocalDateTime.now().plusDays(30))
            .endTime(LocalDateTime.now().plusDays(31))
            .imageUrl("https://images.unsplash.com/photo-1466611653911-95081537e5b7")
            .mediaKey("earth_day_005")
            .locationDetail("Công viên Gia Định, Phú Nhuận, TP.HCM")
            .latitude("10.8003")
            .longitude("106.6800")
            .status(EventStatus.UPCOMING)
            .note("Sự kiện có sự tham gia của nhiều tổ chức môi trường quốc tế")
            .build();
    event5.setCreatedBy(1L);
    event5.setUpdatedBy(1L);
    event5 = eventRepository.save(event5);

    addEventMedia(
        event5,
        List.of(
            "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09",
            "https://images.unsplash.com/photo-1593113646773-028c64a8f1b8",
            "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09"));

    // Event 6: Workshop nhỏ
    Event event6 =
        Event.builder()
            .code("EVT006")
            .name("Workshop Làm Túi Vải từ Quần Áo Cũ")
            .description(
                "Hướng dẫn cách tái chế quần áo cũ thành túi vải thời trang, độc đáo. Giảm thiểu rác thải dệt may.")
            .startTime(LocalDateTime.now().plusDays(5))
            .endTime(LocalDateTime.now().plusDays(5).plusHours(3))
            .imageUrl("https://images.unsplash.com/photo-1591047139829-d91aecb6caea")
            .mediaKey("workshop_bag_006")
            .locationDetail("Cà phê Xanh, Quận Bình Thạnh, TP.HCM")
            .latitude("10.8124")
            .longitude("106.7048")
            .status(EventStatus.UPCOMING)
            .note("Mang theo quần áo cũ, kéo, kim chỉ")
            .build();
    event6.setCreatedBy(1L);
    event6.setUpdatedBy(1L);
    event6 = eventRepository.save(event6);

    addEventMedia(
        event6,
        List.of(
            "https://images.unsplash.com/photo-1582735689369-4fe89db7114c",
            "https://images.unsplash.com/photo-1591047139829-d91aecb6caea"));

    // Event 7: Sự kiện trồng cây
    Event event7 =
        Event.builder()
            .code("EVT007")
            .name("Trồng 1000 Cây Xanh cho Sài Gòn")
            .description(
                "Chiến dịch trồng cây quy mô lớn nhằm tăng diện tích cây xanh, cải thiện chất lượng không khí tại TP.HCM.")
            .startTime(LocalDateTime.now().plusDays(20))
            .endTime(LocalDateTime.now().plusDays(20).plusHours(6))
            .imageUrl("https://images.unsplash.com/photo-1542601098-3adb3b87c6e3")
            .mediaKey("tree_planting_007")
            .locationDetail("Khu đô thị Phú Mỹ Hưng, Quận 7, TP.HCM")
            .latitude("10.7280")
            .longitude("106.7197")
            .status(EventStatus.UPCOMING)
            .note("Mang theo xẻng, nước uống")
            .build();
    event7.setCreatedBy(1L);
    event7.setUpdatedBy(1L);
    event7 = eventRepository.save(event7);

    addEventMedia(
        event7,
        List.of(
            "https://images.unsplash.com/photo-1542601098-3adb3b87c6e3",
            "https://images.unsplash.com/photo-1466692476868-aef1dfb1e735",
            "https://images.unsplash.com/photo-1542601098-b0e6dd2fb72e"));

    log.info("Initialized {} events successfully", eventRepository.count());
  }

  private void addEventMedia(Event event, List<String> imageUrls) {
    List<EventMedia> mediaList = new ArrayList<>();
    for (int i = 0; i < imageUrls.size(); i++) {
      String imageUrl = imageUrls.get(i);
      EventMedia media =
          EventMedia.builder()
              .event(event)
              .mediaKey(event.getMediaKey() + "_media_" + (i + 1))
              .imageUrl(imageUrl)
              .build();
      media.setCreatedBy(1L);
      mediaList.add(media);
    }
    eventMediaRepository.saveAll(mediaList);
    log.info("Added {} media items for event: {}", mediaList.size(), event.getCode());
  }
}
