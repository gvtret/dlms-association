#include "dlms/association/association_client.hpp"

#include "dlms/apdu/acse.hpp"
#include "dlms/apdu/initiate.hpp"
#include "dlms/apdu/xdlms.hpp"

namespace dlms {
namespace association {

namespace {

bool IsProfileOk(dlms::profile::ProfileStatus status)
{
  return status == dlms::profile::ProfileStatus::Ok ||
         status == dlms::profile::ProfileStatus::AlreadyOpen;
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
  const dlms::apdu::AcseApdu aarq =
    dlms::apdu::MakeAarqWithInitiateRequest(xdlms);

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

  if (options_.authenticationMode != AuthenticationMode::None) {
    return AssociationStatus::UnsupportedAuthentication;
  }

  if (options_.proposedDlmsVersionNumber == 0 ||
      options_.clientMaxReceivePduSize == 0) {
    return AssociationStatus::InvalidArgument;
  }

  return AssociationStatus::Ok;
}

} // namespace association
} // namespace dlms
