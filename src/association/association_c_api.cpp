#include "dlms/association/association_c_api.h"

#include "dlms/association/association_client.hpp"

#include <memory>
#include <vector>

struct dlms_association_client_t
{
  dlms::profile::IApduChannel* channel;
  dlms::association::IHighLevelSecurityStrategy* highLevelSecurity;
  dlms::association::AssociationClient* client;
};

namespace {

constexpr std::size_t kDefaultReceiveBufferSize = 2048u;

dlms_association_status_t ToCStatus(
  dlms::association::AssociationStatus status)
{
  return static_cast<dlms_association_status_t>(static_cast<int>(status));
}

dlms::association::AssociationStatus ToCppStatus(
  dlms_association_status_t status)
{
  return static_cast<dlms::association::AssociationStatus>(
    static_cast<int>(status));
}

dlms::profile::ProfileStatus ToProfileStatus(
  dlms_association_status_t status)
{
  switch (ToCppStatus(status)) {
  case dlms::association::AssociationStatus::Ok:
    return dlms::profile::ProfileStatus::Ok;
  case dlms::association::AssociationStatus::InvalidArgument:
    return dlms::profile::ProfileStatus::InvalidArgument;
  case dlms::association::AssociationStatus::ChannelOpenFailed:
    return dlms::profile::ProfileStatus::OpenFailed;
  case dlms::association::AssociationStatus::ChannelCloseFailed:
    return dlms::profile::ProfileStatus::WriteFailed;
  case dlms::association::AssociationStatus::SendFailed:
    return dlms::profile::ProfileStatus::WriteFailed;
  case dlms::association::AssociationStatus::ReceiveFailed:
    return dlms::profile::ProfileStatus::ReadFailed;
  case dlms::association::AssociationStatus::DecodeFailed:
    return dlms::profile::ProfileStatus::InvalidFrame;
  case dlms::association::AssociationStatus::NegotiationFailed:
    return dlms::profile::ProfileStatus::InvalidFrame;
  case dlms::association::AssociationStatus::UnsupportedApplicationContext:
  case dlms::association::AssociationStatus::UnsupportedAuthentication:
    return dlms::profile::ProfileStatus::UnsupportedFeature;
  case dlms::association::AssociationStatus::InvalidState:
  case dlms::association::AssociationStatus::AlreadyAssociated:
  case dlms::association::AssociationStatus::EncodeFailed:
  case dlms::association::AssociationStatus::AssociationRejected:
  case dlms::association::AssociationStatus::InternalError:
    return dlms::profile::ProfileStatus::InternalError;
  }

  return dlms::profile::ProfileStatus::InternalError;
}

dlms_association_state_t ToCState(
  dlms::association::AssociationState state)
{
  switch (state) {
  case dlms::association::AssociationState::Closed:
    return DLMS_ASSOCIATION_STATE_CLOSED;
  case dlms::association::AssociationState::Open:
    return DLMS_ASSOCIATION_STATE_OPEN;
  case dlms::association::AssociationState::Associating:
    return DLMS_ASSOCIATION_STATE_ASSOCIATING;
  case dlms::association::AssociationState::Associated:
    return DLMS_ASSOCIATION_STATE_ASSOCIATED;
  }

  return DLMS_ASSOCIATION_STATE_CLOSED;
}

dlms::association::ApplicationContext ToCppApplicationContext(
  dlms_association_application_context_t context)
{
  (void)context;
  return dlms::association::ApplicationContext::LogicalNameNoCiphering;
}

dlms::association::AuthenticationMode ToCppAuthenticationMode(
  dlms_association_authentication_mode_t mode)
{
  switch (mode) {
  case DLMS_ASSOCIATION_AUTHENTICATION_LOW_LEVEL_SECURITY:
    return dlms::association::AuthenticationMode::LowLevelSecurity;
  case DLMS_ASSOCIATION_AUTHENTICATION_HIGH_LEVEL_SECURITY:
    return dlms::association::AuthenticationMode::HighLevelSecurity;
  case DLMS_ASSOCIATION_AUTHENTICATION_NONE:
    return dlms::association::AuthenticationMode::None;
  }

  return dlms::association::AuthenticationMode::None;
}

dlms::association::HighLevelSecurityMechanism ToCppHlsMechanism(
  dlms_association_hls_mechanism_t mechanism)
{
  switch (mechanism) {
  case DLMS_ASSOCIATION_HLS_MECHANISM_HIGH:
    return dlms::association::HighLevelSecurityMechanism::HlsHigh;
  case DLMS_ASSOCIATION_HLS_MECHANISM_MD5:
    return dlms::association::HighLevelSecurityMechanism::HlsMd5;
  case DLMS_ASSOCIATION_HLS_MECHANISM_SHA1:
    return dlms::association::HighLevelSecurityMechanism::HlsSha1;
  case DLMS_ASSOCIATION_HLS_MECHANISM_GMAC:
    return dlms::association::HighLevelSecurityMechanism::HlsGmac;
  case DLMS_ASSOCIATION_HLS_MECHANISM_UNKNOWN:
    return dlms::association::HighLevelSecurityMechanism::Unknown;
  }

  return dlms::association::HighLevelSecurityMechanism::Unknown;
}

class CHighLevelSecurityStrategy
  : public dlms::association::IHighLevelSecurityStrategy
{
public:
  CHighLevelSecurityStrategy(
    const dlms_association_hls_callbacks_t& callbacks,
    void* userData)
    : callbacks_(callbacks)
    , userData_(userData)
  {
  }

  dlms::association::HighLevelSecurityMechanism Mechanism() const override
  {
    return ToCppHlsMechanism(callbacks_.mechanism(userData_));
  }

  dlms::association::AssociationStatus BuildInitialChallenge(
    std::vector<std::uint8_t>& output) const override
  {
    std::vector<std::uint8_t> buffer(kDefaultReceiveBufferSize);
    std::size_t writtenSize = 0u;
    const dlms_association_status_t status =
      callbacks_.build_initial_challenge(userData_,
                                         &buffer[0],
                                         buffer.size(),
                                         &writtenSize);
    if (status != DLMS_ASSOCIATION_STATUS_OK) {
      return ToCppStatus(status);
    }
    if (writtenSize > buffer.size()) {
      return dlms::association::AssociationStatus::InvalidArgument;
    }

    output.assign(buffer.begin(), buffer.begin() + writtenSize);
    return dlms::association::AssociationStatus::Ok;
  }

private:
  dlms_association_hls_callbacks_t callbacks_;
  void* userData_;
};

bool ValidHlsCallbacks(const dlms_association_hls_callbacks_t* callbacks)
{
  return callbacks != 0 &&
    callbacks->mechanism != 0 &&
    callbacks->build_initial_challenge != 0;
}

dlms::association::AssociationOptions ToCppOptions(
  const dlms_association_options_t* options,
  const dlms::association::IHighLevelSecurityStrategy* highLevelSecurity)
{
  dlms::association::AssociationOptions cppOptions =
    dlms::association::DefaultAssociationOptions();
  if (options == 0) {
    return cppOptions;
  }

  cppOptions.applicationContext =
    ToCppApplicationContext(options->application_context);
  cppOptions.authenticationMode =
    ToCppAuthenticationMode(options->authentication_mode);
  if (options->low_level_security_credential != 0 &&
      options->low_level_security_credential_size != 0) {
    cppOptions.lowLevelSecurityCredential.assign(
      options->low_level_security_credential,
      options->low_level_security_credential +
        options->low_level_security_credential_size);
  }
  cppOptions.highLevelSecurity = highLevelSecurity;
  cppOptions.proposedDlmsVersionNumber =
    options->proposed_dlms_version_number;
  cppOptions.proposedConformance.bytes[0] = options->proposed_conformance[0];
  cppOptions.proposedConformance.bytes[1] = options->proposed_conformance[1];
  cppOptions.proposedConformance.bytes[2] = options->proposed_conformance[2];
  cppOptions.clientMaxReceivePduSize =
    options->client_max_receive_pdu_size;
  return cppOptions;
}

bool ValidCallbacks(const dlms_association_channel_callbacks_t* callbacks)
{
  return callbacks != 0 &&
    callbacks->open != 0 &&
    callbacks->close != 0 &&
    callbacks->send != 0 &&
    callbacks->receive != 0;
}

class CApduChannelAdapter : public dlms::profile::IApduChannel
{
public:
  CApduChannelAdapter(
    const dlms_association_channel_callbacks_t& callbacks,
    std::size_t receiveBufferSize)
    : callbacks_(callbacks)
    , receiveBufferSize_(receiveBufferSize == 0
        ? kDefaultReceiveBufferSize
        : receiveBufferSize)
    , open_(false)
  {
  }

  dlms::profile::ProfileStatus Open() override
  {
    const dlms_association_status_t status =
      callbacks_.open(callbacks_.user_data);
    if (status == DLMS_ASSOCIATION_STATUS_OK) {
      open_ = true;
    }
    return ToProfileStatus(status);
  }

  dlms::profile::ProfileStatus Close() override
  {
    const dlms_association_status_t status =
      callbacks_.close(callbacks_.user_data);
    if (status == DLMS_ASSOCIATION_STATUS_OK) {
      open_ = false;
    }
    return ToProfileStatus(status);
  }

  bool IsOpen() const override
  {
    return open_;
  }

  dlms::profile::ProfileStatus SendApdu(
    dlms::profile::ProfileByteView apdu) override
  {
    return ToProfileStatus(callbacks_.send(callbacks_.user_data,
                                           apdu.data,
                                           apdu.size));
  }

  dlms::profile::ProfileStatus ReceiveApdu(
    std::vector<std::uint8_t>& apdu) override
  {
    std::vector<std::uint8_t> buffer(receiveBufferSize_);
    std::size_t writtenSize = 0u;
    const dlms_association_status_t status =
      callbacks_.receive(callbacks_.user_data,
                         buffer.empty() ? 0 : &buffer[0],
                         buffer.size(),
                         &writtenSize);
    if (status != DLMS_ASSOCIATION_STATUS_OK) {
      return ToProfileStatus(status);
    }
    if (writtenSize > buffer.size()) {
      return dlms::profile::ProfileStatus::InvalidLength;
    }

    apdu.assign(buffer.begin(), buffer.begin() + writtenSize);
    return dlms::profile::ProfileStatus::Ok;
  }

  dlms::profile::ProfileStatus ReceiveApdu(
    dlms::profile::ProfileMutableBuffer output) override
  {
    if (output.data == 0 && output.size != 0) {
      return dlms::profile::ProfileStatus::InvalidArgument;
    }

    std::size_t writtenSize = 0u;
    const dlms_association_status_t status =
      callbacks_.receive(callbacks_.user_data,
                         output.data,
                         output.size,
                         &writtenSize);
    if (output.writtenSize != 0) {
      *output.writtenSize = writtenSize;
    }
    return ToProfileStatus(status);
  }

private:
  dlms_association_channel_callbacks_t callbacks_;
  std::size_t receiveBufferSize_;
  bool open_;
};

void CopyResult(
  const dlms::association::AssociationResult& input,
  dlms_association_result_t* output)
{
  output->negotiated_dlms_version_number =
    input.negotiatedDlmsVersionNumber;
  output->negotiated_conformance[0] = input.negotiatedConformance.bytes[0];
  output->negotiated_conformance[1] = input.negotiatedConformance.bytes[1];
  output->negotiated_conformance[2] = input.negotiatedConformance.bytes[2];
  output->server_max_receive_pdu_size = input.serverMaxReceivePduSize;
  output->vaa_name = input.vaaName;
  output->has_aare_result = input.hasAareResult ? 1 : 0;
  output->aare_result = input.aareResult;
  output->has_aare_diagnostic = input.hasAareDiagnostic ? 1 : 0;
  output->aare_diagnostic = input.aareDiagnostic;
}

} // namespace

void dlms_association_default_options(
  dlms_association_options_t* options)
{
  if (options == 0) {
    return;
  }

  const dlms::association::AssociationOptions cppOptions =
    dlms::association::DefaultAssociationOptions();
  options->application_context =
    DLMS_ASSOCIATION_APPLICATION_CONTEXT_LN_NO_CIPHERING;
  options->authentication_mode = DLMS_ASSOCIATION_AUTHENTICATION_NONE;
  options->low_level_security_credential = 0;
  options->low_level_security_credential_size = 0u;
  options->high_level_security = 0;
  options->high_level_security_user_data = 0;
  options->proposed_dlms_version_number =
    cppOptions.proposedDlmsVersionNumber;
  options->proposed_conformance[0] = cppOptions.proposedConformance.bytes[0];
  options->proposed_conformance[1] = cppOptions.proposedConformance.bytes[1];
  options->proposed_conformance[2] = cppOptions.proposedConformance.bytes[2];
  options->client_max_receive_pdu_size =
    cppOptions.clientMaxReceivePduSize;
  options->receive_buffer_size = kDefaultReceiveBufferSize;
}

dlms_association_client_t* dlms_association_create_client_from_callbacks(
  const dlms_association_channel_callbacks_t* callbacks,
  const dlms_association_options_t* options)
{
  if (!ValidCallbacks(callbacks)) {
    return 0;
  }

  try {
    std::unique_ptr<CApduChannelAdapter> channel(
      new CApduChannelAdapter(*callbacks,
                              options == 0
                                ? kDefaultReceiveBufferSize
                                : options->receive_buffer_size));
    std::unique_ptr<dlms::association::IHighLevelSecurityStrategy> hls;
    if (options != 0 && ValidHlsCallbacks(options->high_level_security)) {
      hls.reset(new CHighLevelSecurityStrategy(
        *options->high_level_security,
        options->high_level_security_user_data));
    }
    std::unique_ptr<dlms::association::AssociationClient> client(
      new dlms::association::AssociationClient(*channel,
                                               ToCppOptions(options,
                                                            hls.get())));
    std::unique_ptr<dlms_association_client_t> handle(
      new dlms_association_client_t);
    handle->channel = channel.release();
    handle->highLevelSecurity = hls.release();
    handle->client = client.release();
    return handle.release();
  } catch (...) {
    return 0;
  }
}

void dlms_association_destroy_client(
  dlms_association_client_t* client)
{
  if (client == 0) {
    return;
  }

  delete client->client;
  client->client = 0;
  delete client->highLevelSecurity;
  client->highLevelSecurity = 0;
  delete client->channel;
  client->channel = 0;
  delete client;
}

dlms_association_status_t dlms_association_open(
  dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }

  try {
    return ToCStatus(client->client->Open());
  } catch (...) {
    return DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR;
  }
}

dlms_association_status_t dlms_association_close(
  dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }

  try {
    return ToCStatus(client->client->Close());
  } catch (...) {
    return DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR;
  }
}

dlms_association_status_t dlms_association_establish(
  dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }

  try {
    return ToCStatus(client->client->Establish());
  } catch (...) {
    return DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR;
  }
}

dlms_association_status_t dlms_association_release(
  dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }

  try {
    return ToCStatus(client->client->Release());
  } catch (...) {
    return DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR;
  }
}

dlms_association_state_t dlms_association_get_state(
  const dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return DLMS_ASSOCIATION_STATE_CLOSED;
  }

  try {
    return ToCState(client->client->State());
  } catch (...) {
    return DLMS_ASSOCIATION_STATE_CLOSED;
  }
}

int dlms_association_is_associated(
  const dlms_association_client_t* client)
{
  if (client == 0 || client->client == 0) {
    return 0;
  }

  try {
    return client->client->IsAssociated() ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

dlms_association_status_t dlms_association_get_result(
  const dlms_association_client_t* client,
  dlms_association_result_t* result)
{
  if (client == 0 || client->client == 0 || result == 0) {
    return DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT;
  }

  try {
    CopyResult(client->client->Result(), result);
    return DLMS_ASSOCIATION_STATUS_OK;
  } catch (...) {
    return DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR;
  }
}
