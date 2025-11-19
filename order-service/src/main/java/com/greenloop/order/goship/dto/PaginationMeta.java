package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PaginationMeta {

    @JsonProperty("pagination")
    private Pagination pagination;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Pagination {

        @JsonProperty("count")
        private Integer count;

        @JsonProperty("current_page")
        private Integer currentPage;

        @JsonProperty("per_page")
        private Integer perPage;

        @JsonProperty("total")
        private Integer total;

        @JsonProperty("total_pages")
        private Integer totalPages;

        @JsonProperty("links")
        private Links links;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Links {

        @JsonProperty("next")
        private String next;

        @JsonProperty("previous")
        private String previous;
    }
}
