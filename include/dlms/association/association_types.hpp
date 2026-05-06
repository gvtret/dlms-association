#pragma once

#include "dlms/apdu/axdr.hpp"
#include "dlms/association/association_status.hpp"

#include <cstdint>

namespace dlms {
namespace association {

enum class AssociationState
{
  Closed,
  Open,
  Associating,
  Associated
};

enum class ApplicationContext
{
  LogicalNameNoCiphering
};

enum class AuthenticationMode
{
  None,
  LowLevelSecurity,
  HighLevelSecurity
};

struct AssociationOptions
{
  ApplicationContext applicationContext;
  AuthenticationMode authenticationMode;
  std::uint8_t proposedDlmsVersionNumber;
  dlms::apdu::AxdrConformance proposedConformance;
  std::uint16_t clientMaxReceivePduSize;
};

struct AssociationResult
{
  std::uint8_t negotiatedDlmsVersionNumber;
  dlms::apdu::AxdrConformance negotiatedConformance;
  std::uint16_t serverMaxReceivePduSize;
  std::uint16_t vaaName;
  bool hasAareResult;
  std::int32_t aareResult;
  bool hasAareDiagnostic;
  std::int32_t aareDiagnostic;
};

AssociationOptions DefaultAssociationOptions();
AssociationResult EmptyAssociationResult();

} // namespace association
} // namespace dlms
