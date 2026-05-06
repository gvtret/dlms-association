#pragma once

#include "dlms/association/association_types.hpp"
#include "dlms/profile/apdu_channel.hpp"

#include <vector>

namespace dlms {
namespace association {

class AssociationClient
{
public:
  AssociationClient(
    dlms::profile::IApduChannel& channel,
    const AssociationOptions& options);

  AssociationStatus Open();
  AssociationStatus Close();
  AssociationStatus Establish();

  AssociationState State() const;
  bool IsAssociated() const;
  const AssociationResult& Result() const;

private:
  AssociationClient(const AssociationClient&);
  AssociationClient& operator=(const AssociationClient&);

  AssociationStatus BuildAarq(std::vector<std::uint8_t>& output) const;
  AssociationStatus DecodeAare(const std::vector<std::uint8_t>& input);
  AssociationStatus ValidateOptions() const;

  dlms::profile::IApduChannel& channel_;
  AssociationOptions options_;
  AssociationState state_;
  AssociationResult result_;
};

} // namespace association
} // namespace dlms
