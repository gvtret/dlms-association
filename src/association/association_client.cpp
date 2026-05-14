#include "dlms/association/association_client.hpp"

#include "dlms/apdu/acse.hpp"
#include "dlms/apdu/initiate.hpp"
#include "dlms/apdu/xdlms.hpp"

namespace dlms {
namespace association {

namespace {

constexpr std::uint8_t kSenderAcseRequirementsTag = 0x8A;
constexpr std::uint8_t kMechanismNameTag = 0x8B;
constexpr std::uint8_t kCalledApInvocationIdTag = 0xA4;
constexpr std::uint8_t kCallingApTitleTag = 0xA6;
constexpr std::uint8_t kRespondingAuthenticationValueTag = 0xAA;
constexpr std::uint8_t kCallingAuthenticationValueTag = 0xAC;
constexpr std::uint8_t kCharstringAuthenticationValueTag = 0x80;
constexpr std::uint8_t kOctetStringTag = 0x04;
constexpr std::size_t kMaxShortBerAuthenticationValueSize = 125u;

bool IsProfileOk(dlms::profile::ProfileStatus status)
{
  return status == dlms::profile::ProfileStatus::Ok ||
         status == dlms::profile::ProfileStatus::AlreadyOpen;
}

bool HlsMechanismId(
  HighLevelSecurityMechanism mechanism,
  std::uint8_t& mechanismId)
{
  switch (mechanism) {
  case HighLevelSecurityMechanism::HlsHigh:
    mechanismId = 2u;
    return true;
  case HighLevelSecurityMechanism::HlsMd5:
    mechanismId = 3u;
    return true;
  case HighLevelSecurityMechanism::HlsSha1:
    mechanismId = 4u;
    return true;
  case HighLevelSecurityMechanism::HlsGmac:
    mechanismId = 5u;
    return true;
  case HighLevelSecurityMechanism::Unknown:
    break;
  }
  return false;
}

dlms::apdu::ByteView MakeByteView(const std::vector<std::uint8_t>& bytes)
{
  dlms::apdu::ByteView view = {};
  view.data = bytes.empty() ? 0 : &bytes[0];
  view.size = bytes.size();
  return view;
}

std::vector<std::uint8_t> MakeSenderAcseRequirementsField()
{
  const std::uint8_t field[] = {
    kSenderAcseRequirementsTag,
    0x02,
    0x07,
    0x80};
  return std::vector<std::uint8_t>(field, field + sizeof(field));
}

std::vector<std::uint8_t> MakeLowLevelSecurityMechanismField()
{
  const std::uint8_t field[] = {
    kMechanismNameTag,
    0x07,
    0x60,
    0x85,
    0x74,
    0x05,
    0x08,
    0x02,
    0x01};
  return std::vector<std::uint8_t>(field, field + sizeof(field));
}

std::vector<std::uint8_t> MakeHighLevelSecurityMechanismField(
  HighLevelSecurityMechanism mechanism)
{
  std::uint8_t mechanismId = 0u;
  HlsMechanismId(mechanism, mechanismId);
  const std::uint8_t field[] = {
    kMechanismNameTag,
    0x07,
    0x60,
    0x85,
    0x74,
    0x05,
    0x08,
    0x02,
    mechanismId};
  return std::vector<std::uint8_t>(field, field + sizeof(field));
}

std::vector<std::uint8_t> MakeCallingAuthenticationValueField(
  const std::vector<std::uint8_t>& credential)
{
  std::vector<std::uint8_t> field;
  field.reserve(4u + credential.size());
  field.push_back(kCallingAuthenticationValueTag);
  field.push_back(static_cast<std::uint8_t>(credential.size() + 2u));
  field.push_back(kCharstringAuthenticationValueTag);
  field.push_back(static_cast<std::uint8_t>(credential.size()));
  field.insert(field.end(), credential.begin(), credential.end());
  return field;
}

void AddLlsAuthenticationFields(
  const AssociationOptions& options,
  dlms::apdu::AarqApdu& aarq,
  std::vector<std::vector<std::uint8_t> >& encodedFields)
{
  if (options.authenticationMode != AuthenticationMode::LowLevelSecurity) {
    return;
  }

  encodedFields.push_back(MakeSenderAcseRequirementsField());
  encodedFields.push_back(MakeLowLevelSecurityMechanismField());
  encodedFields.push_back(
    MakeCallingAuthenticationValueField(options.lowLevelSecurityCredential));

  for (std::size_t i = 0u; i < encodedFields.size(); ++i) {
    dlms::apdu::AcseRawField field = {};
    field.tag = encodedFields[i].empty() ? 0u : encodedFields[i][0];
    field.encoded = MakeByteView(encodedFields[i]);
    aarq.fields.push_back(field);
  }
}

AssociationStatus AddHlsAuthenticationFields(
  const AssociationOptions& options,
  dlms::apdu::AarqApdu& aarq,
  std::vector<std::vector<std::uint8_t> >& encodedFields)
{
  if (options.authenticationMode != AuthenticationMode::HighLevelSecurity) {
    return AssociationStatus::Ok;
  }

  if (options.highLevelSecurity == 0) {
    return AssociationStatus::UnsupportedAuthentication;
  }

  const HighLevelSecurityMechanism mechanism =
    options.highLevelSecurity->Mechanism();
  std::uint8_t mechanismId = 0u;
  if (!HlsMechanismId(mechanism, mechanismId)) {
    return AssociationStatus::UnsupportedAuthentication;
  }

  std::vector<std::uint8_t> challenge;
  if (options.highLevelSecurity->BuildInitialChallenge(challenge) !=
      AssociationStatus::Ok ||
      challenge.empty()) {
    return AssociationStatus::UnsupportedAuthentication;
  }

  if (challenge.size() > kMaxShortBerAuthenticationValueSize) {
    return AssociationStatus::InvalidArgument;
  }

  encodedFields.push_back(MakeSenderAcseRequirementsField());
  encodedFields.push_back(MakeHighLevelSecurityMechanismField(mechanism));
  encodedFields.push_back(MakeCallingAuthenticationValueField(challenge));

  for (std::size_t i = 0u; i < encodedFields.size(); ++i) {
    dlms::apdu::AcseRawField field = {};
    field.tag = encodedFields[i].empty() ? 0u : encodedFields[i][0];
    field.encoded = MakeByteView(encodedFields[i]);
    aarq.fields.push_back(field);
  }

  return AssociationStatus::Ok;
}

bool DecodeAuthenticationValue(
  const dlms::apdu::AcseRawField& field,
  std::uint8_t expectedTag,
  std::vector<std::uint8_t>& output)
{
  if (field.tag != expectedTag ||
      field.encoded.data == 0 ||
      field.encoded.size < 4u) {
    return false;
  }

  const std::uint8_t* bytes = field.encoded.data;
  const std::size_t size = field.encoded.size;
  if (bytes[0] != expectedTag ||
      bytes[1] != size - 2u ||
      bytes[2] != kCharstringAuthenticationValueTag ||
      bytes[3] != size - 4u) {
    return false;
  }

  output.assign(bytes + 4u, bytes + size);
  return true;
}

bool DecodeOctetStringField(
  const dlms::apdu::AcseRawField& field,
  std::vector<std::uint8_t>& output)
{
  if (field.encoded.data == 0 || field.encoded.size < 4u) {
    return false;
  }

  const std::uint8_t* bytes = field.encoded.data;
  const std::size_t size = field.encoded.size;
  if (bytes[0] != field.tag ||
      bytes[1] != size - 2u ||
      bytes[2] != kOctetStringTag ||
      bytes[3] != size - 4u) {
    return false;
  }

  output.assign(bytes + 4u, bytes + size);
  return true;
}

} // namespace

AssociationClient::AssociationClient(
  dlms::profile::IApduChannel& channel,
  const AssociationOptions& options)
  : channel_(channel)
  , options_(options)
  , state_(AssociationState::Closed)
  , result_(EmptyAssociationResult())
{
}

AssociationStatus AssociationClient::Open()
{
  if (state_ != AssociationState::Closed) {
    return AssociationStatus::Ok;
  }

  const dlms::profile::ProfileStatus status = channel_.Open();
  if (!IsProfileOk(status)) {
    return AssociationStatus::ChannelOpenFailed;
  }

  result_ = EmptyAssociationResult();
  state_ = AssociationState::Open;
  return AssociationStatus::Ok;
}

AssociationStatus AssociationClient::Close()
{
  if (state_ == AssociationState::Closed) {
    return AssociationStatus::Ok;
  }

  const dlms::profile::ProfileStatus status = channel_.Close();
  if (status != dlms::profile::ProfileStatus::Ok) {
    return AssociationStatus::ChannelCloseFailed;
  }

  result_ = EmptyAssociationResult();
  state_ = AssociationState::Closed;
  return AssociationStatus::Ok;
}

AssociationStatus AssociationClient::Establish()
{
  if (state_ == AssociationState::Closed) {
    return AssociationStatus::InvalidState;
  }

  if (state_ == AssociationState::Associated) {
    return AssociationStatus::AlreadyAssociated;
  }

  const AssociationStatus optionStatus = ValidateOptions();
  if (optionStatus != AssociationStatus::Ok) {
    return optionStatus;
  }

  state_ = AssociationState::Associating;
  result_ = EmptyAssociationResult();

  std::vector<std::uint8_t> aarq;
  const AssociationStatus buildStatus = BuildAarq(aarq);
  if (buildStatus != AssociationStatus::Ok) {
    state_ = AssociationState::Open;
    return buildStatus;
  }

  dlms::profile::ProfileByteView view = {aarq.empty() ? 0 : &aarq[0], aarq.size()};
  const dlms::profile::ProfileStatus sendStatus = channel_.SendApdu(view);
  if (sendStatus != dlms::profile::ProfileStatus::Ok) {
    state_ = AssociationState::Open;
    return AssociationStatus::SendFailed;
  }

  std::vector<std::uint8_t> aare;
  const dlms::profile::ProfileStatus receiveStatus = channel_.ReceiveApdu(aare);
  if (receiveStatus != dlms::profile::ProfileStatus::Ok) {
    state_ = AssociationState::Open;
    return AssociationStatus::ReceiveFailed;
  }

  const AssociationStatus decodeStatus = DecodeAare(aare);
  if (decodeStatus != AssociationStatus::Ok) {
    state_ = AssociationState::Open;
    return decodeStatus;
  }

  state_ = AssociationState::Associated;
  return AssociationStatus::Ok;
}

AssociationStatus AssociationClient::Release()
{
  if (state_ != AssociationState::Associated) {
    return AssociationStatus::InvalidState;
  }

  std::vector<std::uint8_t> rlrq;
  const AssociationStatus buildStatus = BuildRlrq(rlrq);
  if (buildStatus != AssociationStatus::Ok) {
    return buildStatus;
  }

  dlms::profile::ProfileByteView view = {rlrq.empty() ? 0 : &rlrq[0], rlrq.size()};
  const dlms::profile::ProfileStatus sendStatus = channel_.SendApdu(view);
  if (sendStatus != dlms::profile::ProfileStatus::Ok) {
    return AssociationStatus::SendFailed;
  }

  std::vector<std::uint8_t> rlre;
  const dlms::profile::ProfileStatus receiveStatus = channel_.ReceiveApdu(rlre);
  if (receiveStatus != dlms::profile::ProfileStatus::Ok) {
    return AssociationStatus::ReceiveFailed;
  }

  const AssociationStatus decodeStatus = DecodeRlre(rlre);
  if (decodeStatus != AssociationStatus::Ok) {
    return decodeStatus;
  }

  const dlms::profile::ProfileStatus closeStatus = channel_.Close();
  if (closeStatus != dlms::profile::ProfileStatus::Ok) {
    return AssociationStatus::ChannelCloseFailed;
  }

  result_ = EmptyAssociationResult();
  state_ = AssociationState::Closed;
  return AssociationStatus::Ok;
}

AssociationState AssociationClient::State() const
{
  return state_;
}

bool AssociationClient::IsAssociated() const
{
  return state_ == AssociationState::Associated;
}

const AssociationResult& AssociationClient::Result() const
{
  return result_;
}

AssociationStatus AssociationClient::BuildAarq(
  std::vector<std::uint8_t>& output) const
{
  dlms::apdu::InitiateRequest request =
    dlms::apdu::MakeDefaultInitiateRequest();
  request.proposedDlmsVersionNumber = options_.proposedDlmsVersionNumber;
  request.proposedConformance = options_.proposedConformance;
  request.clientMaxReceivePduSize = options_.clientMaxReceivePduSize;

  const dlms::apdu::XdlmsApdu xdlms(request);
  dlms::apdu::AcseApdu aarq =
    dlms::apdu::MakeAarqWithInitiateRequest(xdlms);
  std::vector<std::vector<std::uint8_t> > encodedFields;
  AddLlsAuthenticationFields(options_, aarq.aarq, encodedFields);
  const AssociationStatus hlsStatus =
    AddHlsAuthenticationFields(options_, aarq.aarq, encodedFields);
  if (hlsStatus != AssociationStatus::Ok) {
    return hlsStatus;
  }

  const dlms::apdu::ApduStatus status =
    dlms::apdu::EncodeAcseApdu(aarq, output);
  return status == dlms::apdu::ApduStatus::Ok
    ? AssociationStatus::Ok
    : AssociationStatus::EncodeFailed;
}

AssociationStatus AssociationClient::DecodeAare(
  const std::vector<std::uint8_t>& input)
{
  if (input.empty()) {
    return AssociationStatus::DecodeFailed;
  }

  dlms::apdu::AcseApdu apdu = {};
  const dlms::apdu::ApduStatus status =
    dlms::apdu::DecodeAcseApdu(&input[0], input.size(), apdu);
  if (status != dlms::apdu::ApduStatus::Ok ||
      apdu.kind != dlms::apdu::AcseApduKind::Aare) {
    return AssociationStatus::DecodeFailed;
  }

  result_.hasAareResult = apdu.aare.hasResult;
  result_.aareResult = apdu.aare.result;
  result_.hasAareDiagnostic = apdu.aare.hasDiagnostic;
  result_.aareDiagnostic = apdu.aare.diagnostic;

  if (apdu.aare.hasResult && apdu.aare.result != 0) {
    return AssociationStatus::AssociationRejected;
  }

  if (apdu.aare.initiateResponse.negotiatedDlmsVersionNumber == 0 ||
      apdu.aare.initiateResponse.serverMaxReceivePduSize == 0) {
    return AssociationStatus::NegotiationFailed;
  }

  result_.negotiatedDlmsVersionNumber =
    apdu.aare.initiateResponse.negotiatedDlmsVersionNumber;
  result_.negotiatedConformance =
    apdu.aare.initiateResponse.negotiatedConformance;
  result_.serverMaxReceivePduSize =
    apdu.aare.initiateResponse.serverMaxReceivePduSize;
  result_.vaaName = apdu.aare.initiateResponse.vaaName;
  result_.respondingApplicationTitle.clear();

  for (std::size_t i = 0u; i < apdu.aare.fields.size(); ++i) {
    if (apdu.aare.fields[i].tag == kCalledApInvocationIdTag ||
        apdu.aare.fields[i].tag == kCallingApTitleTag) {
      std::vector<std::uint8_t> title;
      if (DecodeOctetStringField(apdu.aare.fields[i], title)) {
        result_.respondingApplicationTitle = title;
        break;
      }
    }
  }

  if (options_.authenticationMode == AuthenticationMode::HighLevelSecurity) {
    result_.highLevelSecurityServerChallenge.clear();
    for (std::size_t i = 0u; i < apdu.aare.fields.size(); ++i) {
      if (apdu.aare.fields[i].tag == kRespondingAuthenticationValueTag) {
        if (!DecodeAuthenticationValue(
              apdu.aare.fields[i],
              kRespondingAuthenticationValueTag,
              result_.highLevelSecurityServerChallenge) ||
            result_.highLevelSecurityServerChallenge.empty()) {
          return AssociationStatus::DecodeFailed;
        }
        return AssociationStatus::Ok;
      }
    }
    return AssociationStatus::DecodeFailed;
  }

  return AssociationStatus::Ok;
}

AssociationStatus AssociationClient::BuildRlrq(
  std::vector<std::uint8_t>& output) const
{
  const dlms::apdu::AcseApdu rlrq = dlms::apdu::MakeRlrq();
  const dlms::apdu::ApduStatus status =
    dlms::apdu::EncodeAcseApdu(rlrq, output);
  return status == dlms::apdu::ApduStatus::Ok
    ? AssociationStatus::Ok
    : AssociationStatus::EncodeFailed;
}

AssociationStatus AssociationClient::DecodeRlre(
  const std::vector<std::uint8_t>& input) const
{
  if (input.empty()) {
    return AssociationStatus::DecodeFailed;
  }

  dlms::apdu::AcseApdu apdu = {};
  const dlms::apdu::ApduStatus status =
    dlms::apdu::DecodeAcseApdu(&input[0], input.size(), apdu);
  if (status != dlms::apdu::ApduStatus::Ok ||
      apdu.kind != dlms::apdu::AcseApduKind::Rlre) {
    return AssociationStatus::DecodeFailed;
  }

  return AssociationStatus::Ok;
}

AssociationStatus AssociationClient::ValidateOptions() const
{
  if (options_.applicationContext != ApplicationContext::LogicalNameNoCiphering) {
    return AssociationStatus::UnsupportedApplicationContext;
  }

  if (options_.authenticationMode == AuthenticationMode::LowLevelSecurity) {
    if (options_.lowLevelSecurityCredential.empty()) {
      return AssociationStatus::UnsupportedAuthentication;
    }
    if (options_.lowLevelSecurityCredential.size() >
        kMaxShortBerAuthenticationValueSize) {
      return AssociationStatus::InvalidArgument;
    }
  }

  if (options_.authenticationMode == AuthenticationMode::HighLevelSecurity) {
    if (options_.highLevelSecurity == 0) {
      return AssociationStatus::UnsupportedAuthentication;
    }
  }

  if (options_.proposedDlmsVersionNumber == 0 ||
      options_.clientMaxReceivePduSize == 0) {
    return AssociationStatus::InvalidArgument;
  }

  return AssociationStatus::Ok;
}

} // namespace association
} // namespace dlms
