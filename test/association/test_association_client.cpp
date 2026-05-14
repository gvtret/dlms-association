#include "dlms/association/association_client.hpp"

#include "dlms/apdu/acse.hpp"
#include "dlms/apdu/apdu_error.hpp"
#include "dlms/profile/profile_types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

class FakeHlsStrategy
  : public dlms::association::IHighLevelSecurityStrategy
{
public:
  FakeHlsStrategy()
    : mechanism(dlms::association::HighLevelSecurityMechanism::HlsGmac)
    , status(dlms::association::AssociationStatus::Ok)
    , mechanismCalls(0)
    , challengeCalls(0)
  {
    challenge.push_back(0x01);
  }

  dlms::association::HighLevelSecurityMechanism Mechanism() const override
  {
    ++mechanismCalls;
    return mechanism;
  }

  dlms::association::AssociationStatus BuildInitialChallenge(
    std::vector<std::uint8_t>& output) const override
  {
    ++challengeCalls;
    output = challenge;
    return status;
  }

  dlms::association::HighLevelSecurityMechanism mechanism;
  dlms::association::AssociationStatus status;
  std::vector<std::uint8_t> challenge;
  mutable int mechanismCalls;
  mutable int challengeCalls;
};

class FakeApduChannel : public dlms::profile::IApduChannel
{
public:
  FakeApduChannel()
    : openStatus(dlms::profile::ProfileStatus::Ok)
    , closeStatus(dlms::profile::ProfileStatus::Ok)
    , sendStatus(dlms::profile::ProfileStatus::Ok)
    , receiveStatus(dlms::profile::ProfileStatus::Ok)
    , open(false)
    , openCalls(0)
    , closeCalls(0)
    , sendCalls(0)
    , receiveCalls(0)
  {
  }

  dlms::profile::ProfileStatus Open()
  {
    ++openCalls;
    if (openStatus == dlms::profile::ProfileStatus::Ok ||
        openStatus == dlms::profile::ProfileStatus::AlreadyOpen) {
      open = true;
    }
    return openStatus;
  }

  dlms::profile::ProfileStatus Close()
  {
    ++closeCalls;
    if (closeStatus == dlms::profile::ProfileStatus::Ok) {
      open = false;
    }
    return closeStatus;
  }

  bool IsOpen() const
  {
    return open;
  }

  dlms::profile::ProfileStatus SendApdu(dlms::profile::ProfileByteView apdu)
  {
    ++sendCalls;
    sent.assign(apdu.data, apdu.data + apdu.size);
    return sendStatus;
  }

  dlms::profile::ProfileStatus ReceiveApdu(std::vector<std::uint8_t>& apdu)
  {
    ++receiveCalls;
    if (receiveStatus == dlms::profile::ProfileStatus::Ok) {
      apdu = nextReceive;
    }
    return receiveStatus;
  }

  dlms::profile::ProfileStatus ReceiveApdu(
    dlms::profile::ProfileMutableBuffer output)
  {
    ++receiveCalls;
    if (receiveStatus != dlms::profile::ProfileStatus::Ok) {
      return receiveStatus;
    }

    if (output.size < nextReceive.size()) {
      return dlms::profile::ProfileStatus::OutputBufferTooSmall;
    }

    for (std::size_t i = 0; i < nextReceive.size(); ++i) {
      output.data[i] = nextReceive[i];
    }
    if (output.writtenSize != 0) {
      *output.writtenSize = nextReceive.size();
    }
    return dlms::profile::ProfileStatus::Ok;
  }

  dlms::profile::ProfileStatus openStatus;
  dlms::profile::ProfileStatus closeStatus;
  dlms::profile::ProfileStatus sendStatus;
  dlms::profile::ProfileStatus receiveStatus;
  bool open;
  int openCalls;
  int closeCalls;
  int sendCalls;
  int receiveCalls;
  std::vector<std::uint8_t> sent;
  std::vector<std::uint8_t> nextReceive;
};

std::vector<std::uint8_t> MakeAareBytes(std::int32_t result)
{
  const std::uint8_t kAare[] = {
    0x61, 0x4E, 0x80, 0x02, 0x02, 0x84, 0xA1, 0x09,
    0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01,
    0x01, 0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05,
    0xA1, 0x03, 0x02, 0x01, 0x0E, 0x88, 0x02, 0x07,
    0x80, 0x89, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08,
    0x02, 0x02, 0xAA, 0x12, 0x80, 0x10, 0xC6, 0x69,
    0x73, 0x51, 0xFF, 0x4A, 0xEC, 0x29, 0xCD, 0xBA,
    0xAB, 0xF2, 0xFB, 0xE3, 0x46, 0x7C, 0xBE, 0x10,
    0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04,
    0x00, 0x40, 0x18, 0x1D, 0x02, 0x00, 0x00, 0x07};

  std::vector<std::uint8_t> output(kAare, kAare + sizeof(kAare));
  output[21] = static_cast<std::uint8_t>(result);
  return output;
}

void InsertRespondingApplicationTitle(
  std::vector<std::uint8_t>& aare,
  std::uint8_t tag)
{
  const std::uint8_t title[] = {
    tag, 0x0A, 0x04, 0x08, 'S', 'R', 'V', 'T', 'I', 'T', 'L', 'E'};
  aare.insert(aare.begin() + 29, title, title + sizeof(title));
  aare[1] = static_cast<std::uint8_t>(aare[1] + sizeof(title));
}

std::vector<std::uint8_t> MakeRlreBytes()
{
  const std::uint8_t kRlre[] = {0x63, 0x00};
  return std::vector<std::uint8_t>(kRlre, kRlre + sizeof(kRlre));
}

std::vector<std::uint8_t> FieldBytes(
  const dlms::apdu::AarqApdu& aarq,
  std::uint8_t tag)
{
  for (std::size_t i = 0u; i < aarq.fields.size(); ++i) {
    if (aarq.fields[i].tag == tag) {
      return std::vector<std::uint8_t>(
        aarq.fields[i].encoded.data,
        aarq.fields[i].encoded.data + aarq.fields[i].encoded.size);
    }
  }
  return std::vector<std::uint8_t>();
}

} // namespace

TEST(AssociationClient, EstablishRequiresOpenChannel)
{
  FakeApduChannel channel;
  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  EXPECT_EQ(dlms::association::AssociationStatus::InvalidState,
            client.Establish());
  EXPECT_EQ(dlms::association::AssociationState::Closed, client.State());
}

TEST(AssociationClient, SuccessfulEstablishSendsAarqAndStoresResult)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());

  EXPECT_TRUE(client.IsAssociated());
  EXPECT_EQ(1, channel.sendCalls);
  EXPECT_EQ(1, channel.receiveCalls);

  dlms::apdu::AcseApdu sent = {};
  ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
            dlms::apdu::DecodeAcseApdu(
              &channel.sent[0],
              channel.sent.size(),
              sent));
  EXPECT_EQ(dlms::apdu::AcseApduKind::Aarq, sent.kind);
  EXPECT_EQ(6u, sent.aarq.initiateRequest.proposedDlmsVersionNumber);

  const dlms::association::AssociationResult& result = client.Result();
  EXPECT_EQ(6u, result.negotiatedDlmsVersionNumber);
  EXPECT_EQ(0x0200u, result.serverMaxReceivePduSize);
  EXPECT_EQ(0x0007u, result.vaaName);
  EXPECT_TRUE(result.hasAareResult);
  EXPECT_EQ(0, result.aareResult);
}

TEST(AssociationClient, RejectedAareReturnsToOpen)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(1);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::AssociationRejected,
            client.Establish());
  EXPECT_EQ(dlms::association::AssociationState::Open, client.State());
  EXPECT_FALSE(client.IsAssociated());
  EXPECT_EQ(1, client.Result().aareResult);
}

TEST(AssociationClient, MalformedAareReturnsDecodeFailed)
{
  FakeApduChannel channel;
  channel.nextReceive.push_back(0x00);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::DecodeFailed,
            client.Establish());
  EXPECT_EQ(dlms::association::AssociationState::Open, client.State());
}

TEST(AssociationClient, ReceiveFailureReturnsReceiveFailed)
{
  FakeApduChannel channel;
  channel.receiveStatus = dlms::profile::ProfileStatus::Timeout;

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::ReceiveFailed,
            client.Establish());
  EXPECT_EQ(dlms::association::AssociationState::Open, client.State());
}

TEST(AssociationClient, UnsupportedAuthenticationIsRejectedBeforeSend)
{
  FakeApduChannel channel;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::UnsupportedAuthentication,
            client.Establish());
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, LowLevelSecurityWithoutCredentialIsRejectedBeforeSend)
{
  FakeApduChannel channel;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::LowLevelSecurity;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::UnsupportedAuthentication,
            client.Establish());
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, LowLevelSecurityCredentialAddsAarqAuthFields)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::LowLevelSecurity;
  options.lowLevelSecurityCredential.push_back('p');
  options.lowLevelSecurityCredential.push_back('w');

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());
  ASSERT_EQ(1, channel.sendCalls);

  dlms::apdu::AcseApdu sent = {};
  ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
            dlms::apdu::DecodeAcseApdu(
              &channel.sent[0],
              channel.sent.size(),
              sent));
  ASSERT_EQ(dlms::apdu::AcseApduKind::Aarq, sent.kind);

  const std::uint8_t expectedRequirements[] = {0x8A, 0x02, 0x07, 0x80};
  const std::uint8_t expectedMechanism[] = {
    0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01};
  const std::uint8_t expectedCredential[] = {
    0xAC, 0x04, 0x80, 0x02, 'p', 'w'};

  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedRequirements,
      expectedRequirements + sizeof(expectedRequirements)),
    FieldBytes(sent.aarq, 0x8A));
  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedMechanism,
      expectedMechanism + sizeof(expectedMechanism)),
    FieldBytes(sent.aarq, 0x8B));
  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedCredential,
      expectedCredential + sizeof(expectedCredential)),
    FieldBytes(sent.aarq, 0xAC));
}

TEST(AssociationClient, LowLevelSecurityRejectsCredentialTooLargeForShortBer)
{
  FakeApduChannel channel;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::LowLevelSecurity;
  options.lowLevelSecurityCredential.assign(126u, 'x');

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::InvalidArgument,
            client.Establish());
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, HighLevelSecurityGmacAddsAarqAuthFields)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);
  FakeHlsStrategy strategy;
  strategy.challenge.clear();
  strategy.challenge.push_back(0xC1);
  strategy.challenge.push_back(0xC2);
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());
  EXPECT_EQ(1, strategy.mechanismCalls);
  EXPECT_EQ(1, strategy.challengeCalls);
  EXPECT_EQ(1, channel.sendCalls);

  dlms::apdu::AcseApdu sent = {};
  ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
            dlms::apdu::DecodeAcseApdu(
              &channel.sent[0],
              channel.sent.size(),
              sent));
  ASSERT_EQ(dlms::apdu::AcseApduKind::Aarq, sent.kind);

  const std::uint8_t expectedRequirements[] = {0x8A, 0x02, 0x07, 0x80};
  const std::uint8_t expectedMechanism[] = {
    0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05};
  const std::uint8_t expectedChallenge[] = {
    0xAC, 0x04, 0x80, 0x02, 0xC1, 0xC2};

  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedRequirements,
      expectedRequirements + sizeof(expectedRequirements)),
    FieldBytes(sent.aarq, 0x8A));
  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedMechanism,
      expectedMechanism + sizeof(expectedMechanism)),
    FieldBytes(sent.aarq, 0x8B));
  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedChallenge,
      expectedChallenge + sizeof(expectedChallenge)),
    FieldBytes(sent.aarq, 0xAC));

  const std::uint8_t expectedServerChallenge[] = {
    0xC6, 0x69, 0x73, 0x51, 0xFF, 0x4A, 0xEC, 0x29,
    0xCD, 0xBA, 0xAB, 0xF2, 0xFB, 0xE3, 0x46, 0x7C};
  EXPECT_EQ(
    std::vector<std::uint8_t>(
      expectedServerChallenge,
      expectedServerChallenge + sizeof(expectedServerChallenge)),
    client.Result().highLevelSecurityServerChallenge);
}

TEST(AssociationClient, AareRespondingApplicationTitleIsExposed)
{
  const std::uint8_t tags[] = {0xA4, 0xA6};
  const std::uint8_t expected[] =
    {'S', 'R', 'V', 'T', 'I', 'T', 'L', 'E'};

  for (std::size_t i = 0u; i < 2u; ++i) {
    FakeApduChannel channel;
    channel.nextReceive = MakeAareBytes(0);
    InsertRespondingApplicationTitle(channel.nextReceive, tags[i]);

    dlms::association::AssociationClient client(
      channel,
      dlms::association::DefaultAssociationOptions());

    ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
    ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());
    EXPECT_EQ(
      std::vector<std::uint8_t>(expected, expected + sizeof(expected)),
      client.Result().respondingApplicationTitle);
  }
}

TEST(AssociationClient, HighLevelSecurityStrategyFailureIsRejected)
{
  FakeApduChannel channel;
  FakeHlsStrategy strategy;
  strategy.status = dlms::association::AssociationStatus::InternalError;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::UnsupportedAuthentication,
            client.Establish());
  EXPECT_EQ(1, strategy.mechanismCalls);
  EXPECT_EQ(1, strategy.challengeCalls);
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, HighLevelSecurityRejectsEmptyChallenge)
{
  FakeApduChannel channel;
  FakeHlsStrategy strategy;
  strategy.challenge.clear();
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::UnsupportedAuthentication,
            client.Establish());
  EXPECT_EQ(1, strategy.mechanismCalls);
  EXPECT_EQ(1, strategy.challengeCalls);
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, HighLevelSecurityRejectsChallengeTooLargeForShortBer)
{
  FakeApduChannel channel;
  FakeHlsStrategy strategy;
  strategy.challenge.assign(126u, 0x11);
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::InvalidArgument,
            client.Establish());
  EXPECT_EQ(1, strategy.mechanismCalls);
  EXPECT_EQ(1, strategy.challengeCalls);
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, HighLevelSecurityUnsupportedMechanismIsRejected)
{
  FakeApduChannel channel;
  FakeHlsStrategy strategy;
  strategy.mechanism =
    dlms::association::HighLevelSecurityMechanism::Unknown;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::UnsupportedAuthentication,
            client.Establish());
  EXPECT_EQ(1, strategy.mechanismCalls);
  EXPECT_EQ(0, strategy.challengeCalls);
  EXPECT_EQ(0, channel.sendCalls);
}

TEST(AssociationClient, HighLevelSecurityMechanismsUseMechanismIds)
{
  const dlms::association::HighLevelSecurityMechanism mechanisms[] = {
    dlms::association::HighLevelSecurityMechanism::HlsHigh,
    dlms::association::HighLevelSecurityMechanism::HlsMd5,
    dlms::association::HighLevelSecurityMechanism::HlsSha1};
  const std::uint8_t ids[] = {0x02, 0x03, 0x04};

  for (std::size_t i = 0u; i < 3u; ++i) {
    FakeApduChannel channel;
    channel.nextReceive = MakeAareBytes(0);
    FakeHlsStrategy strategy;
    strategy.mechanism = mechanisms[i];
    dlms::association::AssociationOptions options =
      dlms::association::DefaultAssociationOptions();
    options.authenticationMode =
      dlms::association::AuthenticationMode::HighLevelSecurity;
    options.highLevelSecurity = &strategy;

    dlms::association::AssociationClient client(channel, options);

    ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
    ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());

    dlms::apdu::AcseApdu sent = {};
    ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
              dlms::apdu::DecodeAcseApdu(
                &channel.sent[0],
                channel.sent.size(),
                sent));
    const std::uint8_t expectedMechanism[] = {
      0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, ids[i]};
    EXPECT_EQ(
      std::vector<std::uint8_t>(
        expectedMechanism,
        expectedMechanism + sizeof(expectedMechanism)),
      FieldBytes(sent.aarq, 0x8B));
  }
}

TEST(AssociationClient, HighLevelSecurityMalformedServerChallengeFailsDecode)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);
  for (std::size_t i = 0u; i + 2u < channel.nextReceive.size(); ++i) {
    if (channel.nextReceive[i] == 0xAA) {
      channel.nextReceive[i + 2u] = 0x81;
      break;
    }
  }

  FakeHlsStrategy strategy;
  dlms::association::AssociationOptions options =
    dlms::association::DefaultAssociationOptions();
  options.authenticationMode =
    dlms::association::AuthenticationMode::HighLevelSecurity;
  options.highLevelSecurity = &strategy;

  dlms::association::AssociationClient client(channel, options);

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::DecodeFailed,
            client.Establish());
  EXPECT_EQ(dlms::association::AssociationState::Open, client.State());
}

TEST(AssociationClient, RepeatedEstablishReportsAlreadyAssociated)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());
  EXPECT_EQ(dlms::association::AssociationStatus::AlreadyAssociated,
            client.Establish());
}

TEST(AssociationClient, CloseReturnsToClosed)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());
  EXPECT_EQ(dlms::association::AssociationStatus::Ok, client.Close());
  EXPECT_EQ(dlms::association::AssociationState::Closed, client.State());
}

TEST(AssociationClient, ReleaseRequiresAssociatedState)
{
  FakeApduChannel channel;

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  EXPECT_EQ(dlms::association::AssociationStatus::InvalidState,
            client.Release());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  EXPECT_EQ(dlms::association::AssociationStatus::InvalidState,
            client.Release());
}

TEST(AssociationClient, SuccessfulReleaseSendsRlrqReceivesRlreAndCloses)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());

  channel.nextReceive = MakeRlreBytes();
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Release());

  EXPECT_EQ(dlms::association::AssociationState::Closed, client.State());
  EXPECT_FALSE(client.IsAssociated());
  EXPECT_EQ(2, channel.sendCalls);
  EXPECT_EQ(2, channel.receiveCalls);
  EXPECT_EQ(1, channel.closeCalls);
  EXPECT_FALSE(channel.open);
  EXPECT_EQ(0u, client.Result().serverMaxReceivePduSize);

  dlms::apdu::AcseApdu sent = {};
  ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
            dlms::apdu::DecodeAcseApdu(
              &channel.sent[0],
              channel.sent.size(),
              sent));
  EXPECT_EQ(dlms::apdu::AcseApduKind::Rlrq, sent.kind);
}

TEST(AssociationClient, MalformedReleaseResponseLeavesAssociated)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());

  channel.nextReceive.clear();
  channel.nextReceive.push_back(0x61);
  EXPECT_EQ(dlms::association::AssociationStatus::DecodeFailed,
            client.Release());
  EXPECT_EQ(dlms::association::AssociationState::Associated, client.State());
  EXPECT_TRUE(client.IsAssociated());
}

TEST(AssociationClient, ReleaseReceiveFailureAllowsCloseFallback)
{
  FakeApduChannel channel;
  channel.nextReceive = MakeAareBytes(0);

  dlms::association::AssociationClient client(
    channel,
    dlms::association::DefaultAssociationOptions());

  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Open());
  ASSERT_EQ(dlms::association::AssociationStatus::Ok, client.Establish());

  channel.receiveStatus = dlms::profile::ProfileStatus::Timeout;
  EXPECT_EQ(dlms::association::AssociationStatus::ReceiveFailed,
            client.Release());
  EXPECT_EQ(dlms::association::AssociationState::Associated, client.State());

  EXPECT_EQ(dlms::association::AssociationStatus::Ok, client.Close());
  EXPECT_EQ(dlms::association::AssociationState::Closed, client.State());
}
