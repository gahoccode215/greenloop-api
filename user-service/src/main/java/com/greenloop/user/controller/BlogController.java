package com.greenloop.user.controller;

import com.greenloop.user.dto.request.BlogCreateRequest;
import com.greenloop.user.dto.request.BlogUpdateRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.BlogResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.service.BlogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/blogs")
@RequiredArgsConstructor
@Tag(name = "Blog Management", description = "APIs for managing blogs")
public class BlogController {

  private final BlogService blogService;

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(
      summary = "Create new blog",
      description = "Admin, Manager and Staff can create new blog with optional thumbnail")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> createBlog(
      @Valid @RequestPart("blog") BlogCreateRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile thumbnail) {

    BlogResponse response = blogService.createBlog(request, thumbnail);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(ApiResponseDTO.success("Tạo blog thành công", response, HttpStatus.CREATED));
  }

  @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(
      summary = "Update blog",
      description =
          "Admin, Manager and Staff can update blogs (Staff: own only, Manager/Admin: all)")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> updateBlog(
      @PathVariable Long id,
      @Valid @RequestPart("blog") BlogUpdateRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile thumbnail) {

    BlogResponse response = blogService.updateBlog(id, request, thumbnail);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật blog thành công", response, HttpStatus.OK));
  }

  @DeleteMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(
      summary = "Delete blog",
      description = "Admin and Manager can delete all blogs, Staff can delete own blogs")
  public ResponseEntity<ApiResponseDTO<Void>> deleteBlog(@PathVariable Long id) {
    blogService.deleteBlog(id);
    return ResponseEntity.ok(ApiResponseDTO.success("Xóa blog thành công", null, HttpStatus.OK));
  }

  @PatchMapping("/{id}/publish")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(summary = "Publish blog", description = "Change blog status to PUBLISHED")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> publishBlog(@PathVariable Long id) {
    BlogResponse response = blogService.publishBlog(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Công khai blog thành công", response, HttpStatus.OK));
  }

  @PatchMapping("/{id}/hide")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(summary = "Hide blog", description = "Change blog status to HIDDEN")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> hideBlog(@PathVariable Long id) {
    BlogResponse response = blogService.hideBlog(id);
    return ResponseEntity.ok(ApiResponseDTO.success("Ẩn blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/{id}")
  @Operation(
      summary = "Get blog detail",
      description =
          "Get blog detail by ID. Customer can only view published blogs, Admin/Manager/Staff can view all blogs")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> getBlogDetail(@PathVariable Long id) {
    BlogResponse response = blogService.getBlogDetail(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/published")
  @Operation(
      summary = "Get published blogs",
      description = "Get list of published blogs with search and pagination. Public access.")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getPublishedBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @Parameter(description = "Search by title or content") @RequestParam(required = false)
          String search,
      @Parameter(description = "Sort field") @RequestParam(defaultValue = "publishedAt")
          String sortBy,
      @Parameter(description = "Sort direction (ASC/DESC)") @RequestParam(defaultValue = "DESC")
          String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getPublishedBlogs(search, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog thành công", response, HttpStatus.OK));
  }

  @GetMapping
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(
      summary = "Get all blogs",
      description =
          "Admin, Manager and Staff can view all blogs with search, filter by status and pagination")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getAllBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @Parameter(description = "Search by title or content") @RequestParam(required = false)
          String search,
      @Parameter(description = "Filter by status (DRAFT/PUBLISHED/HIDDEN)")
          @RequestParam(required = false)
          String status,
      @Parameter(description = "Sort field") @RequestParam(defaultValue = "createdAt")
          String sortBy,
      @Parameter(description = "Sort direction (ASC/DESC)") @RequestParam(defaultValue = "DESC")
          String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getAllBlogs(search, status, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/my-blogs")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  @Operation(
      summary = "Get my blogs",
      description = "Admin, Manager and Staff can view their own blogs with search and pagination")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getMyBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @Parameter(description = "Search by title or content") @RequestParam(required = false)
          String search,
      @Parameter(description = "Sort field") @RequestParam(defaultValue = "createdAt")
          String sortBy,
      @Parameter(description = "Sort direction (ASC/DESC)") @RequestParam(defaultValue = "DESC")
          String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getMyBlogs(search, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog của tôi thành công", response, HttpStatus.OK));
  }
}
