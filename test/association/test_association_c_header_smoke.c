#include "dlms/association/association_c_api.h"

int main(void)
{
  dlms_association_options_t options;
  dlms_association_default_options(&options);
  return DLMS_ASSOCIATION_C_API_VERSION == 1u ? 0 : 1;
}
