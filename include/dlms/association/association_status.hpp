#pragma once

namespace dlms {
namespace association {

enum class AssociationStatus
{
  Ok = 0,
  InvalidArgument = 1,
  InvalidState = 2,
  AlreadyAssociated = 3,
  UnsupportedApplicationContext = 4,
  UnsupportedAuthentication = 5,
  ChannelOpenFailed = 6,
  ChannelCloseFailed = 7,
  SendFailed = 8,
  ReceiveFailed = 9,
  EncodeFailed = 10,
  DecodeFailed = 11,
  AssociationRejected = 12,
  NegotiationFailed = 13,
  InternalError = 14
};

const char* AssociationStatusName(AssociationStatus status);

} // namespace association
} // namespace dlms
