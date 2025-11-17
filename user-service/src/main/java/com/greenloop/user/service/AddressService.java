package com.greenloop.user.service;

import com.greenloop.user.dto.request.AddressRequest;
import com.greenloop.user.dto.response.AddressResponse;
import java.util.List;

public interface AddressService {
  AddressResponse createAddress(Long userId, AddressRequest request);

  AddressResponse updateAddress(Long userId, Long addressId, AddressRequest request);

  void deleteAddress(Long userId, Long addressId);

  List<AddressResponse> getAllAddresses(Long userId);

  AddressResponse getAddressById(Long userId, Long addressId);

  AddressResponse setDefaultAddress(Long userId, Long addressId);

  AddressResponse getDefaultAddress(Long userId);
}
