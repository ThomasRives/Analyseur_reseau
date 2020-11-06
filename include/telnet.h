#ifndef TELNET_H
#define TELNET_H

#define OPT_EOL 255 /* Extended-Options-List */ //!!!!
#define OPT_BIN_TRANS 0 /* Binary Transmission */ //!!!!!!
#define OPT_ECHO 1 /* Echo */ //!!!!!
#define OPT_RECONNEXION 2 /* Reconnection */ //!!!
#define OPT_SUP_GO_AHEAD 3 /* Suppress Go Ahead */ //!!!!
#define OPT_MSG_SIZE_NEG 4 /* Approx Message Size Negotiation */
#define OPT_STATUS 5 /* Status */ //!!!!!!!!!!!!!!!!!!!!!!!!!!!
#define OPT_TIMING_MASK 6 /* Timing Mark */ //!!!!!!!!!!!!!!!!!
#define OPT_REMOTE_CTR 7 /* Remote Controlled Trans and Echo */
#define OPT_OUT_LINE_W 8 /* Output Line Width */
#define OPT_OUT_PG_SIZE 9 /* Output Page Size */
#define OPT_OUT_CARR_RET_DISP 10 /* Output Carriage-Return Disposition */
#define OPT_OUT_HOR_TAB_STOP 11 /* Output Horizontal Tab Stops */
#define OPT_OUT_HOR_TAB_DISP 12 /* Output Horizontal Tab Disposition */
#define OPT_OUT_FORMFEED 13 /* Output Formfeed Disposition */
#define OPT_OUT_VERT_TAB_STOP 14 /* Output Vertical Tabstops */
#define OPT_OUT_VERT_TAB_DISP 15 /* Output Vertical Tab Disposition */
#define OPT_OUT_LINEFEED_DISP 16 /* Output Linefeed Disposition */
#define OPT_EXTENDED_ASCII 17 /* Extended ASCII */
#define OPT_LOGOUT 18 /* Logout */
#define OPT_BYTE_MACR 19 /* Byte Macro */
#define OPT_DATA_ENT_TERM 20 /* Data Entry Terminal */
#define OPT_SUPDUP 21 /* SUPDUP */
#define OPT_SUPDUP_OUT 22 /* SUPDUP Output */
#define OPT_SEND_LOC 23 /* Send Location */
#define OPT_TERM_TYPE 24 /* Terminal Type */
#define OPT_END_REC 25 /* End of Record */
#define OPT_TACACS 26 /* TACACS User Identification */
#define OPT_OUT_MARK 27 /* Output Marking */
#define OPT_TERM_LOC_NB 28 /* Terminal Location Number */
#define OPT_TELNET_3270 29 /* Telnet 3270 Regime */
#define OPT_X3_PAD 30 /* X.3 PAD */
#define OPT_NEG_WIN_SIZE 31 /* Negotiate About Window Size */
#define OPT_TERM_SPEED 32 /* Terminal Speed */
#define OPT_REM_FLOW_CTRL 33 /* Remote Flow Control */
#define OPT_LINEMODE 34 /* Linemode */ //!!!!!!!!!!!
#define OPT_X_DISP_LOC 35 /* X Display Location */
#define OPT_ENV_OPT 36 /* Environment Option */
#define OPT_AUTH_OPT 37 /* Authentication Option */
#define OPT_ENC_OPT 38 /* Encryption Option */
#define OPT_NEW_ENV_OPT 39 /* New Environment Option */
#define OPT_TN3270E 40 /* TN3270E */
#define OPT_XAUTH 41 /* XAUTH */
#define OPT_CHARSET 42 /* CHARSET */
#define OPT_TRSP 43 /* Telnet Remote Serial Port (RSP) */
#define OPT_CPCO 44 /* Com Port Control Option */
#define OPT_TSLE 45 /* Telnet Suppress Local Echo */
#define OPT_TSTLS 46 /* Telnet Start TLS */
#define OPT_KERMIT 47 /* KERMIT */
#define OPT_SEND_URL 48 /* SEND-URL */
#define OPT_FORWARD_X 49 /* FORWARD_X */
#define OPT_TPL 138 /* TELOPT PRAGMA LOGON */
#define OPT_TSSPIL 139 /* TELOPT SSPI LOGON */
#define OPT_TPRAGMAH 140 /* TELOPT PRAGMA HEARTBEAT */

#endif //TELNET_H