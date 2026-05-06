#include "dlms/association/association_c_api.h"

#include "dlms/apdu/acse.hpp"
#include "dlms/apdu/apdu_error.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

struct CallbackChannel
{
  bool open;
  std::vector<std::vector<std::uint8_t> > sends;
  std::vector<std::vector<std::uint8_t> > receives;
  dlms_association_status_t receiveStatus;
};

struct CallbackHls
{
  int mechanismCalls;
  int challengeCalls;
  dlms_association_hls_mechanism_t mechanism;
  dlms_association_status_t challengeStatus;
  std::vector<std::uint8_t> challenge;
};

std::vector<std::uint8_t> MakeAareBytes()
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
  return std::vector<std::uint8_t>(kAare, kAare + sizeof(kAare));
}

std::vector<std::uint8_t> MakeRlreBytes()
{
  const std::uint8_t kRlre[] = {0x63, 0x00};
  return std::vector<std::uint8_t>(kRlre, kRlre + sizeof(kRlre));
}

dlms_association_status_t CallbackOpen(void* userData)
{
  static_cast<CallbackChannel*>(userData)->open = true;
  return DLMS_ASSOCIATION_STATUS_OK;
}

dlms_association_status_t CallbackClose(void* userData)
{
  static_cast<CallbackChannel*>(userData)->open = false;
  return DLMS_ASSOCIATION_STATUS_OK;
}

dlms_association_status_t CallbackSend(
  void* userData,
  const std::uint8_t* input,
  std::size_t inputSize)
{
  CallbackChannel* channel = static_cast<CallbackChannel*>(userData);
  channel->sends.push_back(
    std::vector<std::uint8_t>(input, input + inputSize));
  return DLMS_ASSOCIATION_STATUS_OK;
}

dlms_association_status_t CallbackReceive(
  void* userData,
  std::uint8_t* output,
  std::size_t outputSize,
  std::size_t* writtenSize)
{
  CallbackChannel* channel = static_cast<CallbackChannel*>(userData);
  if (writtenSize != 0) {
    *writtenSize = 0u;
  }
  if (channel->receiveStatus != DLMS_ASSOCIATION_STATUS_OK) {
    return channel->receiveStatus;
  }
  if (channel->receives.empty()) {
    return DLMS_ASSOCIATION_STATUS_RECEIVE_FAILED;
  }

  const std::vector<std::uint8_t> next = channel->receives.front();
  channel->receives.erase(channel->receives.begin());
  if (outputSize < next.size()) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }
  for (std::size_t i = 0; i < next.size(); ++i) {
    output[i] = next[i];
  }
  if (writtenSize != 0) {
    *writtenSize = next.size();
  }
  return DLMS_ASSOCIATION_STATUS_OK;
}

dlms_association_channel_callbacks_t MakeCallbacks(CallbackChannel* channel)
{
  dlms_association_channel_callbacks_t callbacks;
  callbacks.user_data = channel;
  callbacks.open = &CallbackOpen;
  callbacks.close = &CallbackClose;
  callbacks.send = &CallbackSend;
  callbacks.receive = &CallbackReceive;
  return callbacks;
}

dlms_association_hls_mechanism_t CallbackHlsMechanism(void* userData)
{
  CallbackHls* hls = static_cast<CallbackHls*>(userData);
  ++hls->mechanismCalls;
  return hls->mechanism;
}

dlms_association_status_t CallbackHlsChallenge(
  void* userData,
  std::uint8_t* output,
  std::size_t outputSize,
  std::size_t* writtenSize)
{
  CallbackHls* hls = static_cast<CallbackHls*>(userData);
  ++hls->challengeCalls;
  if (writtenSize != 0) {
    *writtenSize = 0u;
  }
  if (hls->challengeStatus != DLMS_ASSOCIATION_STATUS_OK) {
    return hls->challengeStatus;
  }
  if (outputSize < hls->challenge.size()) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }
  for (std::size_t i = 0; i < hls->challenge.size(); ++i) {
    output[i] = hls->challenge[i];
  }
  if (writtenSize != 0) {
    *writtenSize = hls->challenge.size();
  }
  return DLMS_ASSOCIATION_STATUS_OK;
}

dlms_association_hls_callbacks_t MakeHlsCallbacks()
{
  dlms_association_hls_callbacks_t callbacks;
  callbacks.mechanism = &CallbackHlsMechanism;
  callbacks.build_initial_challenge = &CallbackHlsChallenge;
  return callbacks;
}

} // namespace

TEST(AssociationCApi, StatusValuesMatchCppContract)
{
  EXPECT_EQ(1u, DLMS_ASSOCIATION_C_API_VERSION);
  EXPECT_EQ(0, DLMS_ASSOCIATION_STATUS_OK);
  EXPECT_EQ(1, DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT);
  EXPECT_EQ(14, DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR);
  EXPECT_EQ(0, DLMS_ASSOCIATION_STATE_CLOSED);
  EXPECT_EQ(3, DLMS_ASSOCIATION_STATE_ASSOCIATED);
}

TEST(AssociationCApi, DefaultOptionsExposeLnNoAuthentication)
{
  dlms_association_options_t options;
  dlms_association_default_options(&options);

  EXPECT_EQ(sizeof(options), DLMS_ASSOCIATION_OPTIONS_SIZE);
  EXPECT_EQ(DLMS_ASSOCIATION_APPLICATION_CONTEXT_LN_NO_CIPHERING,
            options.application_context);
  EXPECT_EQ(DLMS_ASSOCIATION_AUTHENTICATION_NONE,
            options.authentication_mode);
  EXPECT_EQ(6u, options.proposed_dlms_version_number);
  EXPECT_NE(0u, options.client_max_receive_pdu_size);
  EXPECT_NE(0u, options.receive_buffer_size);
  EXPECT_EQ(nullptr, options.low_level_security_credential);
  EXPECT_EQ(0u, options.low_level_security_credential_size);
  EXPECT_EQ(nullptr, options.high_level_security);
  EXPECT_EQ(nullptr, options.high_level_security_user_data);
}

TEST(AssociationCApi, CallbackClientLifecycle)
{
  CallbackChannel channel;
  channel.open = false;
  channel.receiveStatus = DLMS_ASSOCIATION_STATUS_OK;
  channel.receives.push_back(MakeAareBytes());
  channel.receives.push_back(MakeRlreBytes());

  dlms_association_options_t options;
  dlms_association_default_options(&options);
  dlms_association_channel_callbacks_t callbacks = MakeCallbacks(&channel);

  dlms_association_client_t* client =
    dlms_association_create_client_from_callbacks(&callbacks, &options);
  ASSERT_NE(nullptr, client);

  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_open(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATE_OPEN,
            dlms_association_get_state(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_establish(client));
  EXPECT_EQ(1, dlms_association_is_associated(client));

  dlms_association_result_t result;
  ASSERT_EQ(DLMS_ASSOCIATION_STATUS_OK,
            dlms_association_get_result(client, &result));
  EXPECT_EQ(6u, result.negotiated_dlms_version_number);
  EXPECT_EQ(0x0200u, result.server_max_receive_pdu_size);
  EXPECT_EQ(0x0007u, result.vaa_name);

  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_release(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATE_CLOSED,
            dlms_association_get_state(client));
  EXPECT_EQ(0, dlms_association_is_associated(client));
  EXPECT_FALSE(channel.open);
  ASSERT_EQ(2u, channel.sends.size());

  dlms::apdu::AcseApdu sent = {};
  ASSERT_EQ(dlms::apdu::ApduStatus::Ok,
            dlms::apdu::DecodeAcseApdu(
              &channel.sends[1][0],
              channel.sends[1].size(),
              sent));
  EXPECT_EQ(dlms::apdu::AcseApduKind::Rlrq, sent.kind);

  dlms_association_destroy_client(client);
}

TEST(AssociationCApi, LowLevelSecurityCredentialIsCopiedAndRejected)
{
  CallbackChannel channel;
  channel.open = false;
  channel.receiveStatus = DLMS_ASSOCIATION_STATUS_OK;

  const std::uint8_t credential[] = {'p', 'w'};
  dlms_association_options_t options;
  dlms_association_default_options(&options);
  options.authentication_mode =
    DLMS_ASSOCIATION_AUTHENTICATION_LOW_LEVEL_SECURITY;
  options.low_level_security_credential = credential;
  options.low_level_security_credential_size = sizeof(credential);
  dlms_association_channel_callbacks_t callbacks = MakeCallbacks(&channel);

  dlms_association_client_t* client =
    dlms_association_create_client_from_callbacks(&callbacks, &options);
  ASSERT_NE(nullptr, client);

  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_open(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_UNSUPPORTED_AUTHENTICATION,
            dlms_association_establish(client));
  EXPECT_TRUE(channel.sends.empty());

  dlms_association_destroy_client(client);
}

TEST(AssociationCApi, HighLevelSecurityCallbacksAreDelegatedBeforeReject)
{
  CallbackChannel channel;
  channel.open = false;
  channel.receiveStatus = DLMS_ASSOCIATION_STATUS_OK;
  CallbackHls hls;
  hls.mechanismCalls = 0;
  hls.challengeCalls = 0;
  hls.mechanism = DLMS_ASSOCIATION_HLS_MECHANISM_GMAC;
  hls.challengeStatus = DLMS_ASSOCIATION_STATUS_OK;
  hls.challenge.push_back(0x01);

  dlms_association_options_t options;
  dlms_association_default_options(&options);
  options.authentication_mode =
    DLMS_ASSOCIATION_AUTHENTICATION_HIGH_LEVEL_SECURITY;
  const dlms_association_hls_callbacks_t hlsCallbacks = MakeHlsCallbacks();
  options.high_level_security = &hlsCallbacks;
  options.high_level_security_user_data = &hls;
  dlms_association_channel_callbacks_t callbacks = MakeCallbacks(&channel);

  dlms_association_client_t* client =
    dlms_association_create_client_from_callbacks(&callbacks, &options);
  ASSERT_NE(nullptr, client);

  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_open(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_UNSUPPORTED_AUTHENTICATION,
            dlms_association_establish(client));
  EXPECT_EQ(1, hls.mechanismCalls);
  EXPECT_EQ(1, hls.challengeCalls);
  EXPECT_TRUE(channel.sends.empty());

  dlms_association_destroy_client(client);
}

TEST(AssociationCApi, HighLevelSecurityModeWithoutCallbacksIsRejected)
{
  CallbackChannel channel;
  channel.open = false;
  channel.receiveStatus = DLMS_ASSOCIATION_STATUS_OK;

  dlms_association_options_t options;
  dlms_association_default_options(&options);
  options.authentication_mode =
    DLMS_ASSOCIATION_AUTHENTICATION_HIGH_LEVEL_SECURITY;
  dlms_association_channel_callbacks_t callbacks = MakeCallbacks(&channel);

  dlms_association_client_t* client =
    dlms_association_create_client_from_callbacks(&callbacks, &options);
  ASSERT_NE(nullptr, client);

  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_OK, dlms_association_open(client));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_UNSUPPORTED_AUTHENTICATION,
            dlms_association_establish(client));
  EXPECT_TRUE(channel.sends.empty());

  dlms_association_destroy_client(client);
}

TEST(AssociationCApi, RejectsMissingCallbacksAndNullHandles)
{
  dlms_association_channel_callbacks_t callbacks;
  callbacks.user_data = 0;
  callbacks.open = 0;
  callbacks.close = 0;
  callbacks.send = 0;
  callbacks.receive = 0;

  EXPECT_EQ(nullptr,
            dlms_association_create_client_from_callbacks(&callbacks, 0));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT,
            dlms_association_open(nullptr));
  EXPECT_EQ(DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT,
            dlms_association_get_result(nullptr, nullptr));
  EXPECT_EQ(DLMS_ASSOCIATION_STATE_CLOSED,
            dlms_association_get_state(nullptr));
  EXPECT_EQ(0, dlms_association_is_associated(nullptr));
  dlms_association_destroy_client(nullptr);
}
