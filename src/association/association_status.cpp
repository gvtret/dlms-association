#include "dlms/association/association_status.hpp"

namespace dlms {
namespace association {

const char* AssociationStatusName(AssociationStatus status)
{
  switch (status) {
    case AssociationStatus::Ok:
      return "Ok";
    case AssociationStatus::InvalidArgument:
      return "InvalidArgument";
    case AssociationStatus::InvalidState:
      return "InvalidState";
    case AssociationStatus::AlreadyAssociated:
      return "AlreadyAssociated";
    case AssociationStatus::UnsupportedApplicationContext:
      return "UnsupportedApplicationContext";
    case AssociationStatus::UnsupportedAuthentication:
      return "UnsupportedAuthentication";
    case AssociationStatus::ChannelOpenFailed:
      return "ChannelOpenFailed";
    case AssociationStatus::ChannelCloseFailed:
      return "ChannelCloseFailed";
    case AssociationStatus::SendFailed:
      return "SendFailed";
    case AssociationStatus::ReceiveFailed:
      return "ReceiveFailed";
    case AssociationStatus::EncodeFailed:
      return "EncodeFailed";
    case AssociationStatus::DecodeFailed:
      return "DecodeFailed";
    case AssociationStatus::AssociationRejected:
      return "AssociationRejected";
    case AssociationStatus::NegotiationFailed:
      return "NegotiationFailed";
    case AssociationStatus::InternalError:
      return "InternalError";
  }

  return "Unknown";
}

} // namespace association
} // namespace dlms
