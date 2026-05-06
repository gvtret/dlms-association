#ifndef DLMS_ASSOCIATION_ASSOCIATION_C_API_H
#define DLMS_ASSOCIATION_ASSOCIATION_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DLMS_ASSOCIATION_C_API_VERSION 1u

typedef enum dlms_association_status_t
{
  DLMS_ASSOCIATION_STATUS_OK = 0,
  DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT = 1,
  DLMS_ASSOCIATION_STATUS_INVALID_STATE = 2,
  DLMS_ASSOCIATION_STATUS_ALREADY_ASSOCIATED = 3,
  DLMS_ASSOCIATION_STATUS_UNSUPPORTED_APPLICATION_CONTEXT = 4,
  DLMS_ASSOCIATION_STATUS_UNSUPPORTED_AUTHENTICATION = 5,
  DLMS_ASSOCIATION_STATUS_CHANNEL_OPEN_FAILED = 6,
  DLMS_ASSOCIATION_STATUS_CHANNEL_CLOSE_FAILED = 7,
  DLMS_ASSOCIATION_STATUS_SEND_FAILED = 8,
  DLMS_ASSOCIATION_STATUS_RECEIVE_FAILED = 9,
  DLMS_ASSOCIATION_STATUS_ENCODE_FAILED = 10,
  DLMS_ASSOCIATION_STATUS_DECODE_FAILED = 11,
  DLMS_ASSOCIATION_STATUS_ASSOCIATION_REJECTED = 12,
  DLMS_ASSOCIATION_STATUS_NEGOTIATION_FAILED = 13,
  DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR = 14
} dlms_association_status_t;

typedef enum dlms_association_state_t
{
  DLMS_ASSOCIATION_STATE_CLOSED = 0,
  DLMS_ASSOCIATION_STATE_OPEN = 1,
  DLMS_ASSOCIATION_STATE_ASSOCIATING = 2,
  DLMS_ASSOCIATION_STATE_ASSOCIATED = 3
} dlms_association_state_t;

typedef enum dlms_association_application_context_t
{
  DLMS_ASSOCIATION_APPLICATION_CONTEXT_LN_NO_CIPHERING = 0
} dlms_association_application_context_t;

typedef enum dlms_association_authentication_mode_t
{
  DLMS_ASSOCIATION_AUTHENTICATION_NONE = 0,
  DLMS_ASSOCIATION_AUTHENTICATION_LOW_LEVEL_SECURITY = 1,
  DLMS_ASSOCIATION_AUTHENTICATION_HIGH_LEVEL_SECURITY = 2
} dlms_association_authentication_mode_t;

typedef struct dlms_association_options_t
{
  dlms_association_application_context_t application_context;
  dlms_association_authentication_mode_t authentication_mode;
  uint8_t proposed_dlms_version_number;
  uint8_t proposed_conformance[3];
  uint16_t client_max_receive_pdu_size;
  size_t receive_buffer_size;
} dlms_association_options_t;

#define DLMS_ASSOCIATION_OPTIONS_SIZE \
  (sizeof(dlms_association_options_t))

typedef struct dlms_association_result_t
{
  uint8_t negotiated_dlms_version_number;
  uint8_t negotiated_conformance[3];
  uint16_t server_max_receive_pdu_size;
  uint16_t vaa_name;
  int has_aare_result;
  int32_t aare_result;
  int has_aare_diagnostic;
  int32_t aare_diagnostic;
} dlms_association_result_t;

typedef struct dlms_association_client_t dlms_association_client_t;

typedef dlms_association_status_t (*dlms_association_channel_open_fn)(
  void* user_data);
typedef dlms_association_status_t (*dlms_association_channel_close_fn)(
  void* user_data);
typedef dlms_association_status_t (*dlms_association_channel_send_fn)(
  void* user_data,
  const uint8_t* input,
  size_t input_size);
typedef dlms_association_status_t (*dlms_association_channel_receive_fn)(
  void* user_data,
  uint8_t* output,
  size_t output_size,
  size_t* written_size);

typedef struct dlms_association_channel_callbacks_t
{
  void* user_data;
  dlms_association_channel_open_fn open;
  dlms_association_channel_close_fn close;
  dlms_association_channel_send_fn send;
  dlms_association_channel_receive_fn receive;
} dlms_association_channel_callbacks_t;

void dlms_association_default_options(
  dlms_association_options_t* options);

dlms_association_client_t* dlms_association_create_client_from_callbacks(
  const dlms_association_channel_callbacks_t* callbacks,
  const dlms_association_options_t* options);

void dlms_association_destroy_client(
  dlms_association_client_t* client);

dlms_association_status_t dlms_association_open(
  dlms_association_client_t* client);

dlms_association_status_t dlms_association_close(
  dlms_association_client_t* client);

dlms_association_status_t dlms_association_establish(
  dlms_association_client_t* client);

dlms_association_status_t dlms_association_release(
  dlms_association_client_t* client);

dlms_association_state_t dlms_association_get_state(
  const dlms_association_client_t* client);

int dlms_association_is_associated(
  const dlms_association_client_t* client);

dlms_association_status_t dlms_association_get_result(
  const dlms_association_client_t* client,
  dlms_association_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* DLMS_ASSOCIATION_ASSOCIATION_C_API_H */
