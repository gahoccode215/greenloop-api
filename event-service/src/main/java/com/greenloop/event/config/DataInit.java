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
            .name("Ngày Hội Thu Gom Quần Áo Cũ Quận 1")
            .description(
                "Sự kiện thu gom quần áo, giày dép, túi xách cũ tại trung tâm thành phố. Mang theo quần áo không còn sử dụng để đổi lấy EcoPoint. Tất cả các loại quần áo đều được chấp nhận: áo, quần, váy, đầm, áo khoác, giày, dép, túi xách, phụ kiện. Quần áo sẽ được phân loại, làm sạch và tái chế thành sợi vải mới hoặc chế biến thành các sản phẩm thời trang tái chế. Mỗi kg quần áo được tích 50 EcoPoint.")
            .startTime(LocalDateTime.now().minusDays(1))
            .endTime(LocalDateTime.now().plusDays(2))
            .imageUrl("https://images.unsplash.com/photo-1489987707025-afc232f7ea0f")
            .mediaKey("clothes_collection_001")
            .locationDetail("Công viên Tao Đàn, số 3 Trương Định, Phường Bến Nghé, Quận 1, TP.HCM")
            .latitude("10.7829")
            .longitude("106.6933")
            .status(EventStatus.ONGOING)
            .note(
                "Quần áo cần giặt sạch, phơi khô trước khi mang đến. Sẽ có cân điện tử tại chỗ để đo khối lượng.")
            .build();
    event1.setCreatedBy(1L);
    event1.setUpdatedBy(1L);
    event1 = eventRepository.save(event1);

    addEventMedia(
        event1,
        List.of(
            "https://images.unsplash.com/photo-1489987707025-afc232f7ea0f",
            "https://images.unsplash.com/photo-1558769132-cb1aea2f14e4",
            "https://images.unsplash.com/photo-1523381210434-271e8be1f52b"));

    // Event 2: Sự kiện sắp tới - Gò Vấp
    Event event2 =
        Event.builder()
            .code("EVT002")
            .name("Thu Gom Quần Áo Cũ Cuối Tuần - Gò Vấp")
            .description(
                "Chương trình thu gom quần áo cũ cuối tuần tại Quận Gò Vấp. Đổi quần áo cũ lấy EcoPoint để mua sắm các sản phẩm thời trang tái chế trên hệ thống. Chương trình chấp nhận tất cả các loại quần áo: quần áo trẻ em, người lớn, quần áo mùa đông, mùa hè, giày dép, túi xách. Các món đồ sẽ được cân, phân loại và xử lý theo quy trình tái chế chuẩn quốc tế. Tỉ lệ quy đổi: 1 kg = 50 EcoPoint.")
            .startTime(LocalDateTime.now().plusDays(7))
            .endTime(LocalDateTime.now().plusDays(8))
            .imageUrl("https://images.unsplash.com/photo-1591047139829-d91aecb6caea")
            .mediaKey("clothes_collection_002")
            .locationDetail(
                "Nhà Văn hóa Quận Gò Vấp, số 315 Quang Trung, Phường 10, Quận Gò Vấp, TP.HCM")
            .latitude("10.8387")
            .longitude("106.6621")
            .status(EventStatus.UPCOMING)
            .note(
                "Xe bus miễn phí từ Bến xe Miền Đông lúc 7h sáng. Mang theo túi đựng đồ riêng để tiện di chuyển.")
            .build();
    event2.setCreatedBy(1L);
    event2.setUpdatedBy(1L);
    event2 = eventRepository.save(event2);

    addEventMedia(
        event2,
        List.of(
            "https://images.unsplash.com/photo-1591047139829-d91aecb6caea",
            "https://images.unsplash.com/photo-1594633312681-425c7b97ccd1"));

    // Event 3: Sự kiện đã kết thúc
    Event event3 =
        Event.builder()
            .code("EVT003")
            .name("Thu Gom Quần Áo Cũ Tháng 11 - Quận 3")
            .description(
                "Sự kiện thu gom quần áo cũ đã diễn ra thành công với lượng quần áo thu được 850 kg. Các món đồ đã được phân loại, xử lý và chuyển đến cơ sở tái chế. Tổng số người tham gia: 420 người. Tổng EcoPoint đã trao: 42,500 điểm. Đây là một trong những sự kiện thu gom thành công nhất trong tháng 11.")
            .startTime(LocalDateTime.now().minusDays(10))
            .endTime(LocalDateTime.now().minusDays(8))
            .imageUrl("https://images.unsplash.com/photo-1523381210434-271e8be1f52b")
            .mediaKey("clothes_collection_003")
            .locationDetail(
                "Nhà Văn hóa Thanh Niên, số 4 Phạm Ngọc Thạch, Phường 6, Quận 3, TP.HCM")
            .latitude("10.7756")
            .longitude("106.6917")
            .status(EventStatus.CLOSED)
            .note("Đã thu gom 850 kg quần áo từ 420 người tham gia. Sự kiện vượt kỳ vọng.")
            .build();
    event3.setCreatedBy(1L);
    event3.setUpdatedBy(1L);
    event3 = eventRepository.save(event3);

    addEventMedia(
        event3,
        List.of(
            "https://images.unsplash.com/photo-1523381210434-271e8be1f52b",
            "https://images.unsplash.com/photo-1558769132-cb1aea2f14e4",
            "https://images.unsplash.com/photo-1445205170230-053b83016050"));

    // Event 4: Sự kiện bị hủy
    Event event4 =
        Event.builder()
            .code("EVT004")
            .name("Thu Gom Quần Áo Cũ Quận 7 - Tạm Hoãn")
            .description(
                "Sự kiện thu gom quần áo cũ tại Quận 7 đã tạm hoãn do điều kiện thời tiết không thuận lợi. Chương trình sẽ được tổ chức lại vào cuối tháng này với địa điểm và thời gian mới. Thông tin cập nhật sẽ được thông báo qua email và ứng dụng. Xin lỗi vì sự bất tiện này.")
            .startTime(LocalDateTime.now().plusDays(14))
            .endTime(LocalDateTime.now().plusDays(14).plusHours(6))
            .imageUrl("https://images.unsplash.com/photo-1582735689369-4fe89db7114c")
            .mediaKey("clothes_collection_004")
            .locationDetail(
                "Trung tâm Văn hóa Quận 7, số 788 Nguyễn Văn Linh, Phường Tân Phú, Quận 7, TP.HCM")
            .latitude("10.7321")
            .longitude("106.7196")
            .status(EventStatus.CANCELED)
            .note("Tạm hoãn do mưa lớn. Sẽ tổ chức lại vào cuối tháng.")
            .build();
    event4.setCreatedBy(1L);
    event4.setUpdatedBy(1L);
    event4 = eventRepository.save(event4);

    addEventMedia(event4, List.of("https://images.unsplash.com/photo-1582735689369-4fe89db7114c"));

    // Event 5: Sự kiện lớn sắp tới
    Event event5 =
        Event.builder()
            .code("EVT005")
            .name("Đại Hội Thu Gom Quần Áo Cũ Toàn Thành Phố 2025")
            .description(
                "Sự kiện thu gom quần áo cũ quy mô lớn nhất năm với mục tiêu thu gom 10 tấn quần áo trong 2 ngày. Địa điểm rộng rãi, nhiều điểm tiếp nhận. Có xe bus đưa đón miễn phí từ nhiều điểm trong thành phố. Tỉ lệ quy đổi đặc biệt: 1 kg = 100 EcoPoint (gấp đôi thông thường). Ngoài ra còn có các hoạt động trải nghiệm, trưng bày sản phẩm thời trang tái chế, tư vấn cách phân loại quần áo tại nhà. Dự kiến có hơn 5000 người tham gia.")
            .startTime(LocalDateTime.now().plusDays(30))
            .endTime(LocalDateTime.now().plusDays(31))
            .imageUrl("https://images.unsplash.com/photo-1489987707025-afc232f7ea0f")
            .mediaKey("clothes_collection_005")
            .locationDetail("Công viên Gia Định, số 243 Hoàng Văn Thụ, Phường 8, Phú Nhuận, TP.HCM")
            .latitude("10.8003")
            .longitude("106.6800")
            .status(EventStatus.UPCOMING)
            .note(
                "Sự kiện lớn nhất năm. Gấp đôi EcoPoint: 1 kg = 100 điểm. Đăng ký trước để được ưu tiên.")
            .build();
    event5.setCreatedBy(1L);
    event5.setUpdatedBy(1L);
    event5 = eventRepository.save(event5);

    addEventMedia(
        event5,
        List.of(
            "https://images.unsplash.com/photo-1489987707025-afc232f7ea0f",
            "https://images.unsplash.com/photo-1558769132-cb1aea2f14e4",
            "https://images.unsplash.com/photo-1445205170230-053b83016050"));

    // Event 6: Sự kiện Bình Thạnh
    Event event6 =
        Event.builder()
            .code("EVT006")
            .name("Thu Gom Quần Áo Cũ Tháng 12 - Bình Thạnh")
            .description(
                "Chương trình thu gom quần áo cũ thường xuyên tại Quận Bình Thạnh. Mang quần áo, giày dép không còn mặc đến để đổi EcoPoint. Không giới hạn số lượng, càng nhiều càng tốt. Quần áo được phân loại ngay tại chỗ và cân trọng lượng chính xác. Điểm EcoPoint được cộng vào tài khoản ngay lập tức thông qua quét QR code. Thời gian diễn ra trong 4 tiếng vào sáng Chủ nhật.")
            .startTime(LocalDateTime.now().plusDays(5))
            .endTime(LocalDateTime.now().plusDays(5).plusHours(4))
            .imageUrl("https://images.unsplash.com/photo-1591047139829-d91aecb6caea")
            .mediaKey("clothes_collection_006")
            .locationDetail(
                "Nhà Văn hóa Quận Bình Thạnh, số 123 Xô Viết Nghệ Tĩnh, Phường 21, Bình Thạnh, TP.HCM")
            .latitude("10.8124")
            .longitude("106.7048")
            .status(EventStatus.UPCOMING)
            .note("Không giới hạn số lượng. Điểm EcoPoint cộng ngay lập tức qua QR code.")
            .build();
    event6.setCreatedBy(1L);
    event6.setUpdatedBy(1L);
    event6 = eventRepository.save(event6);

    addEventMedia(
        event6,
        List.of(
            "https://images.unsplash.com/photo-1591047139829-d91aecb6caea",
            "https://images.unsplash.com/photo-1582735689369-4fe89db7114c"));

    // Event 7: Sự kiện Phú Mỹ Hưng
    Event event7 =
        Event.builder()
            .code("EVT007")
            .name("Thu Gom Quần Áo Cũ Khu Đô Thị Phú Mỹ Hưng")
            .description(
                "Sự kiện thu gom quần áo cũ tại khu đô thị Phú Mỹ Hưng, phục vụ cư dân trong khu và lân cận. Chấp nhận mọi loại quần áo: quần áo thường ngày, quần áo công sở, đồ mùa đông, giày cao gót, giày thể thao, túi xách, phụ kiện. Địa điểm thuận tiện, có bãi đỗ xe rộng rãi. Quần áo được cân và tính điểm ngay, không phải chờ đợi. Tỉ lệ: 1 kg = 50 EcoPoint.")
            .startTime(LocalDateTime.now().plusDays(20))
            .endTime(LocalDateTime.now().plusDays(20).plusHours(6))
            .imageUrl("https://images.unsplash.com/photo-1523381210434-271e8be1f52b")
            .mediaKey("clothes_collection_007")
            .locationDetail("Crescent Mall, số 101 Tôn Dật Tiên, Phường Tân Phú, Quận 7, TP.HCM")
            .latitude("10.7280")
            .longitude("106.7197")
            .status(EventStatus.UPCOMING)
            .note("Bãi đỗ xe miễn phí. Cân và tính điểm tại chỗ, không chờ đợi.")
            .build();
    event7.setCreatedBy(1L);
    event7.setUpdatedBy(1L);
    event7 = eventRepository.save(event7);

    addEventMedia(
        event7,
        List.of(
            "https://images.unsplash.com/photo-1523381210434-271e8be1f52b",
            "https://images.unsplash.com/photo-1558769132-cb1aea2f14e4",
            "https://images.unsplash.com/photo-1489987707025-afc232f7ea0f"));

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
