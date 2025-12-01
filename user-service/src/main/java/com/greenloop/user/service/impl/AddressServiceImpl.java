package com.greenloop.user.service.impl;

import com.greenloop.user.dto.request.AddressRequest;
import com.greenloop.user.dto.response.AddressResponse;
import com.greenloop.user.entity.User;
import com.greenloop.user.entity.UserAddress;
import com.greenloop.user.exception.AddressNotFoundException;
import com.greenloop.user.exception.UserNotFoundException;
import com.greenloop.user.repository.UserAddressRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AddressService;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AddressServiceImpl implements AddressService {

  private final UserAddressRepository addressRepository;
  private final UserRepository userRepository;

  @Override
  @Transactional
  public AddressResponse createAddress(Long userId, AddressRequest request) {

    User user = findUserById(userId);
    boolean shouldSetDefault = determineDefaultStatus(userId, request.getIsDefault());

    if (shouldSetDefault) {
      unsetAllDefaultAddresses(userId);
    }

    UserAddress address = buildAddressEntity(request, user, shouldSetDefault);
    UserAddress savedAddress = addressRepository.save(address);

    return mapToResponse(savedAddress);
  }

  @Override
  @Transactional
  public AddressResponse updateAddress(Long userId, Long addressId, AddressRequest request) {

    UserAddress address = findAddressByIdAndUserId(addressId, userId);
    updateAddressFields(address, request);
    handleDefaultAddressChange(address, request.getIsDefault(), userId);

    UserAddress updatedAddress = addressRepository.save(address);

    return mapToResponse(updatedAddress);
  }

  @Override
  @Transactional
  public void deleteAddress(Long userId, Long addressId) {

    UserAddress address = findAddressByIdAndUserId(addressId, userId);
    boolean wasDefault = address.getIsDefault();

    addressRepository.delete(address);

    if (wasDefault) {
      reassignDefaultAddress(userId);
    }
  }

  @Override
  @Transactional(readOnly = true)
  public List<AddressResponse> getAllAddresses(Long userId) {

    List<UserAddress> addresses = addressRepository.findByUserIdOrderByIsDefaultDescIdDesc(userId);

    return addresses.stream().map(this::mapToResponse).collect(Collectors.toList());
  }

  @Override
  @Transactional(readOnly = true)
  public AddressResponse getAddressById(Long userId, Long addressId) {

    UserAddress address = findAddressByIdAndUserId(addressId, userId);
    return mapToResponse(address);
  }

  @Override
  @Transactional
  public AddressResponse setDefaultAddress(Long userId, Long addressId) {

    UserAddress address = findAddressByIdAndUserId(addressId, userId);

    unsetAllDefaultAddresses(userId);
    address.setIsDefault(true);
    addressRepository.save(address);

    return mapToResponse(address);
  }

  @Override
  @Transactional(readOnly = true)
  public AddressResponse getDefaultAddress(Long userId) {

    UserAddress address =
        addressRepository
            .findDefaultAddressByUserId(userId)
            .orElseThrow(
                () ->
                    new AddressNotFoundException(
                        "Không tìm thấy địa chỉ mặc định cho người dùng: " + userId));

    return mapToResponse(address);
  }

  private User findUserById(Long userId) {
    return userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
  }

  private UserAddress findAddressByIdAndUserId(Long addressId, Long userId) {
    return addressRepository
        .findByIdAndUserId(addressId, userId)
        .orElseThrow(() -> new AddressNotFoundException(addressId, userId));
  }

  private boolean determineDefaultStatus(Long userId, Boolean requestedDefault) {
    long addressCount = addressRepository.countByUserId(userId);
    boolean isFirstAddress = addressCount == 0;
    boolean explicitlyRequested = Boolean.TRUE.equals(requestedDefault);
    return isFirstAddress || explicitlyRequested;
  }

  private void unsetAllDefaultAddresses(Long userId) {
    addressRepository
        .findByUserIdAndIsDefaultTrue(userId)
        .ifPresent(
            address -> {
              address.setIsDefault(false);
              addressRepository.save(address);
            });
  }

  private UserAddress buildAddressEntity(AddressRequest request, User user, boolean isDefault) {
    return UserAddress.builder()
        .recipientName(request.getRecipientName())
        .recipientPhone(request.getRecipientPhone())
        .addressLine(request.getAddressLine())
        .ward(request.getWard())
        .wardCode(request.getWardCode())
        .district(request.getDistrict())
        .districtName(request.getDistrictName())
        .city(request.getCity())
        .cityName(request.getCityName())
        .deliveryNote(request.getDeliveryNote())
        .isDefault(isDefault)
        .user(user)
        .build();
  }

  private void updateAddressFields(UserAddress address, AddressRequest request) {
    address.setRecipientName(request.getRecipientName());
    address.setRecipientPhone(request.getRecipientPhone());
    address.setAddressLine(request.getAddressLine());
    address.setWard(request.getWard());
    address.setWardCode(request.getWardCode());
    address.setDistrict(request.getDistrict());
    address.setDistrictName(request.getDistrictName());
    address.setCity(request.getCity());
    address.setCityName(request.getCityName());
    address.setDeliveryNote(request.getDeliveryNote());
  }

  private void handleDefaultAddressChange(
      UserAddress address, Boolean requestedDefault, Long userId) {
    if (Boolean.TRUE.equals(requestedDefault) && !address.getIsDefault()) {
      unsetAllDefaultAddresses(userId);
      address.setIsDefault(true);
    }
  }

  private void reassignDefaultAddress(Long userId) {
    List<UserAddress> remainingAddresses =
        addressRepository.findByUserIdOrderByIsDefaultDescIdDesc(userId);

    UserAddress firstAddress = remainingAddresses.get(0);
    firstAddress.setIsDefault(true);
    addressRepository.save(firstAddress);
  }

  private AddressResponse mapToResponse(UserAddress address) {
    return AddressResponse.builder()
        .id(address.getId())
        .recipientName(address.getRecipientName())
        .recipientPhone(address.getRecipientPhone())
        .addressLine(address.getAddressLine())
        .ward(address.getWard())
        .wardCode(address.getWardCode())
        .district(address.getDistrict())
        .districtName(address.getDistrictName())
        .city(address.getCity())
        .cityName(address.getCityName())
        .isDefault(address.getIsDefault())
        .deliveryNote(address.getDeliveryNote())
        .build();
  }
}
