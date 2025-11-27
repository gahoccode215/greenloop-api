package com.greenloop.user.dto.response;

import com.greenloop.user.enums.BlogStatus;
import java.time.LocalDateTime;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BlogResponse {
  private Long id;
  private String title;
  private String content;
  private String thumbnailUrl;
  private BlogStatus status;
  private LocalDateTime publishedAt;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
  private Long authorId;
  private String authorName;
  private String authorEmail;
  private String authorAvatarUrl;
}
