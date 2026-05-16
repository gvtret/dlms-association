#include "dlms/association/association_status.hpp"
#include "dlms/association/association_types.hpp"

#include <gtest/gtest.h>

namespace {

TEST(AssociationTypes, DefaultOptionsUseDlmsInitiateDefaults)
{
  const dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();

  EXPECT_EQ(dlms::association::ApplicationContext::LogicalNameNoCiphering,
            options.applicationContext);
  EXPECT_EQ(dlms::association::AuthenticationMode::None,
            options.authenticationMode);
  EXPECT_TRUE(options.lowLevelSecurityCredential.empty());
  EXPECT_EQ(0, options.highLevelSecurity);
  EXPECT_EQ(0, options.traceSink);
  EXPECT_EQ(6u, options.proposedDlmsVersionNumber);
  EXPECT_EQ(0x00u, options.proposedConformance.bytes[0]);
  EXPECT_EQ(0x7eu, options.proposedConformance.bytes[1]);
  EXPECT_EQ(0x1fu, options.proposedConformance.bytes[2]);
  EXPECT_EQ(0x0200u, options.clientMaxReceivePduSize);
}

TEST(AssociationTypes, EmptyResultClearsNegotiatedContext)
{
  const dlms::association::AssociationResult result =
    dlms::association::EmptyAssociationResult();

  EXPECT_EQ(0u, result.negotiatedDlmsVersionNumber);
  EXPECT_EQ(0u, result.serverMaxReceivePduSize);
  EXPECT_EQ(0u, result.vaaName);
  EXPECT_FALSE(result.hasAareResult);
  EXPECT_FALSE(result.hasAareDiagnostic);
}

TEST(AssociationStatus, NamesStableValues)
{
  EXPECT_STREQ(
    "AssociationRejected",
    dlms::association::AssociationStatusName(
      dlms::association::AssociationStatus::AssociationRejected));
}

} // namespace
