package com.greenloop.product.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PageResponseDTO<T> implements Serializable {

  private List<T> content;

  private int pageNumber;

  private int pageSize;

  private long totalElements;

  private int totalPages;

  private boolean first;

  private boolean last;

  private boolean empty;
}
