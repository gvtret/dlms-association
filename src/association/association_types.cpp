#include "dlms/association/association_types.hpp"

#include "dlms/apdu/initiate.hpp"

namespace dlms {
namespace association {

AssociationOptions DefaultAssociationOptions()
{
  const dlms::apdu::InitiateRequest request =
    dlms::apdu::MakeDefaultInitiateRequest();

  AssociationOptions options;
  options.applicationContext = ApplicationContext::LogicalNameNoCiphering;
  options.authenticationMode = AuthenticationMode::None;
  options.lowLevelSecurityCredential.clear();
  options.highLevelSecurity = 0;
  options.traceSink = 0;
  options.hasProposedQualityOfService = request.hasProposedQualityOfService;
  options.proposedQualityOfService = request.proposedQualityOfService;
  options.proposedDlmsVersionNumber = request.proposedDlmsVersionNumber;
  options.proposedConformance = request.proposedConformance;
  options.clientMaxReceivePduSize = request.clientMaxReceivePduSize;
  return options;
}

AssociationResult EmptyAssociationResult()
{
  AssociationResult result;
  result.negotiatedDlmsVersionNumber = 0;
  result.negotiatedConformance.bytes[0] = 0;
  result.negotiatedConformance.bytes[1] = 0;
  result.negotiatedConformance.bytes[2] = 0;
  result.serverMaxReceivePduSize = 0;
  result.vaaName = 0;
  result.hasAareResult = false;
  result.aareResult = 0;
  result.hasAareDiagnostic = false;
  result.aareDiagnostic = 0;
  result.highLevelSecurityServerChallenge.clear();
  result.respondingApplicationTitle.clear();
  return result;
}

} // namespace association
} // namespace dlms
