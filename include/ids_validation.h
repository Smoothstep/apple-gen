// Keep it as low level as possible for maximum support
#ifndef _IDS_VALIDATION_H_
#define _IDS_VALIDATION_H_

#include <stdint.h>

#ifdef _WIN32
  #ifdef _BUILD_SHARED
    #ifdef DLL_EXPORT
      #define EXPORT_CRYPT __declspec(dllexport)
    #else
      #define EXPORT_CRYPT __declspec(dllimport)
    #endif
  #else
    #define EXPORT_CRYPT
  #endif
#else
  #define EXPORT_CRYPT
#endif

extern "C" 
{
  enum NacError
  {
    NAC_NO_ERROR,
    NAC_INVALID_PARAMETER,
    NAC_INIT_ERROR,
    NAC_REQUEST_ERROR,
    NAC_SIGN_ERROR,
    NAC_ENCRYPT_ERROR,
    NAC_FREE_ERROR,
    NAC_INVALID_CALL
  };

  struct MachineInfo
  {
      // board id [Mac-27AD2F918AE68F65]
      char board_id[64];  

      // boot uuid string [uuid4]
      char root_disk_uuid[38];

      // product name [MacPro7,1]
      char product_name[64];

      // platform serial string [uuid4]
      char platform_serial[38];

      // platform uuid string [uuid4]
      char platform_uuid[38];
      
      // mlb [C02923200KVKN3YAG]
      char mlb[64];

      // rom bytes
      uint8_t rom[6];

      // mac address bytes
      uint8_t mac[6];

      // Optional Gq3489ugfi
      uint8_t platform_serial_encrypted[17];

      // Optional Fyp98tpgj
      uint8_t platform_uuid_encrypted[17];

      // Optional kbjfrfpoJU
      uint8_t root_disk_uuid_encrypted[17];

      // Optional oycqAZloTNDm
      uint8_t rom_encrypted[17];

      // Optional abKPld1EcMni
      uint8_t mlb_encrypted[17];
  };

  struct ValidationContext;
  struct ValidationSignature;

  struct ValidationRequest
  {
    uint8_t bytes[338];
  };

  struct SessionData
  {
    uint8_t bytes[698];
  };

  struct ValidationCert
  {
    uint8_t bytes[2385];
  };

  EXPORT_CRYPT NacError build_machine_info(
      const char* board_id,
      const char* root_disk_uuid,
      const char* product_name,
      const char* platform_serial,
      const char* platform_uuid,
      const char* mlb,
      const char* rom,
      const char* mac,
      MachineInfo* info
  );

  EXPORT_CRYPT NacError encrypt_io_data(
    const void* data, 
    unsigned int size, 
    void* output);

  EXPORT_CRYPT NacError init_nac_request(
    const ValidationCert* cert, 
    const MachineInfo* machine_info, 
    ValidationContext** out_context, 
    ValidationRequest** out_request);

  EXPORT_CRYPT NacError sign_nac_request(
    ValidationContext* context, 
    const SessionData* session,
    ValidationSignature** out_validation,
    unsigned int* out_validation_length);

  EXPORT_CRYPT NacError free_nac(
    ValidationContext* data);

  EXPORT_CRYPT void free_data(
    void* data);
};

#endif //_IDS_VALIDATION_H_