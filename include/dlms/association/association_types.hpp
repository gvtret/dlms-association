#pragma once

#include "dlms/apdu/axdr.hpp"
#include "dlms/association/association_status.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

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

enum class HighLevelSecurityMechanism
{
  Unknown,
  HlsHigh,
  HlsMd5,
  HlsSha1,
  HlsGmac
};

class IHighLevelSecurityStrategy
{
public:
  virtual ~IHighLevelSecurityStrategy()
  {
  }

  virtual HighLevelSecurityMechanism Mechanism() const = 0;
  virtual AssociationStatus BuildInitialChallenge(
    std::vector<std::uint8_t>& output) const = 0;
};

enum class AssociationTraceKind
{
  AarqBuilt,
  AarqBuildFailed,
  AareReceiveFailed
};

struct AssociationTraceField
{
  std::uint8_t tag;
  std::size_t encodedSize;
};

struct AssociationTraceEvent
{
  AssociationTraceKind kind;
  AssociationStatus status;
  ApplicationContext applicationContext;
  AuthenticationMode authenticationMode;
  HighLevelSecurityMechanism hlsMechanism;
  bool hasProposedQualityOfService;
  std::int8_t proposedQualityOfService;
  std::uint8_t proposedDlmsVersionNumber;
  dlms::apdu::AxdrConformance proposedConformance;
  std::uint16_t clientMaxReceivePduSize;
  std::size_t encodedAarqSize;
  std::size_t callingAuthenticationValueSize;
  const AssociationTraceField* fields;
  std::size_t fieldCount;
};

class IAssociationTraceSink
{
public:
  virtual ~IAssociationTraceSink()
  {
  }

  virtual void OnAssociationTrace(const AssociationTraceEvent& event) = 0;
};

struct AssociationOptions
{
  ApplicationContext applicationContext;
  AuthenticationMode authenticationMode;
  std::vector<std::uint8_t> lowLevelSecurityCredential;
  const IHighLevelSecurityStrategy* highLevelSecurity;
  IAssociationTraceSink* traceSink;
  bool hasProposedQualityOfService;
  std::int8_t proposedQualityOfService;
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
  std::vector<std::uint8_t> highLevelSecurityServerChallenge;
  std::vector<std::uint8_t> respondingApplicationTitle;
};

AssociationOptions DefaultAssociationOptions();
AssociationResult EmptyAssociationResult();

} // namespace association
} // namespace dlms
