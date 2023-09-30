#![allow(non_camel_case_types)]
use std::os::raw::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_void};

use libc::timeval;

// Error return codes
pub const SSH_OK: c_int = 0;
pub const SSH_ERROR: c_int = -1;
pub const SSH_AGAIN: c_int = -2;
pub const SSH_EOF: c_int = -127;

// log
pub const SSH_LOG_NOLOG: c_int = 0;
pub const SSH_LOG_WARNING: c_int = 1;
pub const SSH_LOG_PROTOCOL: c_int = 2;
pub const SSH_LOG_PACKET: c_int = 3;
pub const SSH_LOG_FUNCTIONS: c_int = 4;

// status flags
pub const SSH_CLOSED: c_int = 1;
pub const SSH_READ_PENDING: c_int = 2;
pub const SSH_CLOSED_ERROR: c_int = 4;
pub const SSH_WRITE_PENDING: c_int = 8;

// callback
pub const SSH_SOCKET_FLOW_WRITEWILLBLOCK: c_int = 1;
pub const SSH_SOCKET_FLOW_WRITEWONTBLOCK: c_int = 2;
pub const SSH_SOCKET_EXCEPTION_EOF: c_int = 1;
pub const SSH_SOCKET_EXCEPTION_ERROR: c_int = 2;
pub const SSH_SOCKET_CONNECTED_OK: c_int = 1;
pub const SSH_SOCKET_CONNECTED_ERROR: c_int = 2;
pub const SSH_SOCKET_CONNECTED_TIMEOUT: c_int = 3;

pub const SSH_PACKET_USED: c_int = 1;
pub const SSH_PACKET_NOT_USED: c_int = 2;

// SFTP attributes
pub const SSH_FILEXFER_ATTR_SIZE: c_uint = 1;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: c_uint = 4;
pub const SSH_FILEXFER_ATTR_ACCESSTIME: c_uint = 8;
pub const SSH_FILEXFER_ATTR_ACMODTIME: c_uint = 8;
pub const SSH_FILEXFER_ATTR_CREATETIME: c_uint = 16;
pub const SSH_FILEXFER_ATTR_MODIFYTIME: c_uint = 32;
pub const SSH_FILEXFER_ATTR_ACL: c_uint = 64;
pub const SSH_FILEXFER_ATTR_OWNERGROUP: c_uint = 128;
pub const SSH_FILEXFER_ATTR_SUBSECOND_TIMES: c_uint = 256;
pub const SSH_FILEXFER_ATTR_EXTENDED: c_uint = 2147483648;
pub const SSH_FILEXFER_ATTR_UIDGID: c_uint = 2;

// SFTP types
pub const SSH_FILEXFER_TYPE_REGULAR: c_int = 1;
pub const SSH_FILEXFER_TYPE_DIRECTORY: c_int = 2;
pub const SSH_FILEXFER_TYPE_SYMLINK: c_int = 3;
pub const SSH_FILEXFER_TYPE_SPECIAL: c_int = 4;
pub const SSH_FILEXFER_TYPE_UNKNOWN: c_int = 5;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg(windows)]
pub struct fd_set {
    pub fd_count: c_uint,
    pub fd_array: [usize; 64usize],
}

#[cfg(unix)]
pub type fd_set = libc::fd_set;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_counter_struct {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub in_packets: u64,
    pub out_packets: u64,
}
pub type ssh_counter = *mut ssh_counter_struct;

pub enum ssh_agent_struct {}
pub type ssh_agent = *mut ssh_agent_struct;

pub enum ssh_buffer_struct {}
pub type ssh_buffer = *mut ssh_buffer_struct;

pub enum ssh_channel_struct {}
pub type ssh_channel = *mut ssh_channel_struct;

pub enum ssh_message_struct {}
pub type ssh_message = *mut ssh_message_struct;

pub enum ssh_pcap_file_struct {}
pub type ssh_pcap_file = *mut ssh_pcap_file_struct;

pub enum ssh_key_struct {}
pub type ssh_key = *mut ssh_key_struct;

pub enum ssh_scp_struct {}
pub type ssh_scp = *mut ssh_scp_struct;

pub enum ssh_session_struct {}
pub type ssh_session = *mut ssh_session_struct;

pub enum ssh_string_struct {}
pub type ssh_string = *mut ssh_string_struct;

pub enum ssh_event_struct {}
pub type ssh_event = *mut ssh_event_struct;

pub enum ssh_connector_struct {}
pub type ssh_connector = *mut ssh_connector_struct;

pub type ssh_gssapi_creds = *mut c_void;
#[cfg(windows)]
pub type socket_t = libc::SOCKET;
#[cfg(not(windows))]
pub type socket_t = libc::c_int;

pub type ssh_auth_e = c_int;
pub const SSH_AUTH_SUCCESS: ssh_auth_e = 0;
pub const SSH_AUTH_DENIED: ssh_auth_e = 1;
pub const SSH_AUTH_PARTIAL: ssh_auth_e = 2;
pub const SSH_AUTH_INFO: ssh_auth_e = 3;
pub const SSH_AUTH_AGAIN: ssh_auth_e = 4;
pub const SSH_AUTH_ERROR: ssh_auth_e = -1;

// auth flags
pub const SSH_AUTH_METHOD_UNKNOWN: c_int = 0;
pub const SSH_AUTH_METHOD_NONE: c_int = 1;
pub const SSH_AUTH_METHOD_PASSWORD: c_int = 2;
pub const SSH_AUTH_METHOD_PUBLICKEY: c_int = 4;
pub const SSH_AUTH_METHOD_HOSTBASED: c_int = 8;
pub const SSH_AUTH_METHOD_INTERACTIVE: c_int = 16;
pub const SSH_AUTH_METHOD_GSSAPI_MIC: c_int = 32;

pub type ssh_requests_e = c_int;
pub const SSH_REQUEST_AUTH: ssh_requests_e = 1;
pub const SSH_REQUEST_CHANNEL_OPEN: ssh_requests_e = 2;
pub const SSH_REQUEST_CHANNEL: ssh_requests_e = 3;
pub const SSH_REQUEST_SERVICE: ssh_requests_e = 4;
pub const SSH_REQUEST_GLOBAL: ssh_requests_e = 5;

pub type ssh_channel_type_e = c_int;
pub const SSH_CHANNEL_UNKNOWN: ssh_channel_type_e = 0;
pub const SSH_CHANNEL_SESSION: ssh_channel_type_e = 1;
pub const SSH_CHANNEL_DIRECT_TCPIP: ssh_channel_type_e = 2;
pub const SSH_CHANNEL_FORWARDED_TCPIP: ssh_channel_type_e = 3;
pub const SSH_CHANNEL_X11: ssh_channel_type_e = 4;
pub const SSH_CHANNEL_AUTH_AGENT: ssh_channel_type_e = 5;

pub type ssh_channel_requests_e = c_int;
pub const SSH_CHANNEL_REQUEST_UNKNOWN: ssh_channel_requests_e = 0;
pub const SSH_CHANNEL_REQUEST_PTY: ssh_channel_requests_e = 1;
pub const SSH_CHANNEL_REQUEST_EXEC: ssh_channel_requests_e = 2;
pub const SSH_CHANNEL_REQUEST_SHELL: ssh_channel_requests_e = 3;
pub const SSH_CHANNEL_REQUEST_ENV: ssh_channel_requests_e = 4;
pub const SSH_CHANNEL_REQUEST_SUBSYSTEM: ssh_channel_requests_e = 5;
pub const SSH_CHANNEL_REQUEST_WINDOW_CHANGE: ssh_channel_requests_e = 6;
pub const SSH_CHANNEL_REQUEST_X11: ssh_channel_requests_e = 7;

pub type ssh_global_requests_e = c_int;
pub const SSH_GLOBAL_REQUEST_UNKNOWN: ssh_global_requests_e = 0;
pub const SSH_GLOBAL_REQUEST_TCPIP_FORWARD: ssh_global_requests_e = 1;
pub const SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD: ssh_global_requests_e = 2;
pub const SSH_GLOBAL_REQUEST_KEEPALIVE: ssh_global_requests_e = 3;
pub const SSH_GLOBAL_REQUEST_NO_MORE_SESSIONS: ssh_global_requests_e = 4;

pub type ssh_publickey_state_e = c_int;
pub const SSH_PUBLICKEY_STATE_ERROR: ssh_publickey_state_e = -1;
pub const SSH_PUBLICKEY_STATE_NONE: ssh_publickey_state_e = 0;
pub const SSH_PUBLICKEY_STATE_VALID: ssh_publickey_state_e = 1;
pub const SSH_PUBLICKEY_STATE_WRONG: ssh_publickey_state_e = 2;

pub type ssh_server_known_e = c_int;
pub const SSH_SERVER_ERROR: ssh_server_known_e = -1;
pub const SSH_SERVER_NOT_KNOWN: ssh_server_known_e = 0;
pub const SSH_SERVER_KNOWN_OK: ssh_server_known_e = 1;
pub const SSH_SERVER_KNOWN_CHANGED: ssh_server_known_e = 2;
pub const SSH_SERVER_FOUND_OTHER: ssh_server_known_e = 3;
pub const SSH_SERVER_FILE_NOT_FOUND: ssh_server_known_e = 4;

pub type ssh_known_hosts_e = c_int;
pub const SSH_KNOWN_HOSTS_ERROR: ssh_known_hosts_e = -2;
pub const SSH_KNOWN_HOSTS_NOT_FOUND: ssh_known_hosts_e = -1;
pub const SSH_KNOWN_HOSTS_UNKNOWN: ssh_known_hosts_e = 0;
pub const SSH_KNOWN_HOSTS_OK: ssh_known_hosts_e = 1;
pub const SSH_KNOWN_HOSTS_CHANGED: ssh_known_hosts_e = 2;
pub const SSH_KNOWN_HOSTS_OTHER: ssh_known_hosts_e = 3;

pub type ssh_error_types_e = c_int;
pub const SSH_NO_ERROR: ssh_error_types_e = 0;
pub const SSH_REQUEST_DENIED: ssh_error_types_e = 1;
pub const SSH_FATAL: ssh_error_types_e = 2;
pub const SSH_EINTR: ssh_error_types_e = 3;

pub type ssh_keytypes_e = c_int;
pub const SSH_KEYTYPE_UNKNOWN: ssh_keytypes_e = 0;
pub const SSH_KEYTYPE_DSS: ssh_keytypes_e = 1;
pub const SSH_KEYTYPE_RSA: ssh_keytypes_e = 2;
pub const SSH_KEYTYPE_RSA1: ssh_keytypes_e = 3;
pub const SSH_KEYTYPE_ECDSA: ssh_keytypes_e = 4;
pub const SSH_KEYTYPE_ED25519: ssh_keytypes_e = 5;
pub const SSH_KEYTYPE_DSS_CERT01: ssh_keytypes_e = 6;
pub const SSH_KEYTYPE_RSA_CERT01: ssh_keytypes_e = 7;
pub const SSH_KEYTYPE_ECDSA_P256: ssh_keytypes_e = 8;
pub const SSH_KEYTYPE_ECDSA_P384: ssh_keytypes_e = 9;
pub const SSH_KEYTYPE_ECDSA_P521: ssh_keytypes_e = 10;
pub const SSH_KEYTYPE_ECDSA_P256_CERT01: ssh_keytypes_e = 11;
pub const SSH_KEYTYPE_ECDSA_P384_CERT01: ssh_keytypes_e = 12;
pub const SSH_KEYTYPE_ECDSA_P521_CERT01: ssh_keytypes_e = 13;
pub const SSH_KEYTYPE_ED25519_CERT01: ssh_keytypes_e = 14;
pub const SSH_KEYTYPE_SK_ECDSA: ssh_keytypes_e = 15;
pub const SSH_KEYTYPE_SK_ECDSA_CERT01: ssh_keytypes_e = 16;
pub const SSH_KEYTYPE_SK_ED25519: ssh_keytypes_e = 17;
pub const SSH_KEYTYPE_SK_ED25519_CERT01: ssh_keytypes_e = 18;

pub type ssh_keycmp_e = c_int;
pub const SSH_KEY_CMP_PUBLIC: ssh_keycmp_e = 0;
pub const SSH_KEY_CMP_PRIVATE: ssh_keycmp_e = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_knownhosts_entry {
    pub hostname: *mut c_char,
    pub unparsed: *mut c_char,
    pub publickey: ssh_key,
    pub comment: *mut c_char,
}

pub type ssh_control_master_options_e = c_int;
pub const SSH_CONTROL_MASTER_NO: ssh_control_master_options_e = 0;
pub const SSH_CONTROL_MASTER_AUTO: ssh_control_master_options_e = 1;
pub const SSH_CONTROL_MASTER_YES: ssh_control_master_options_e = 2;
pub const SSH_CONTROL_MASTER_ASK: ssh_control_master_options_e = 3;
pub const SSH_CONTROL_MASTER_AUTOASK: ssh_control_master_options_e = 4;

pub type ssh_options_e = c_int;
pub const SSH_OPTIONS_HOST: ssh_options_e = 0;
pub const SSH_OPTIONS_PORT: ssh_options_e = 1;
pub const SSH_OPTIONS_PORT_STR: ssh_options_e = 2;
pub const SSH_OPTIONS_FD: ssh_options_e = 3;
pub const SSH_OPTIONS_USER: ssh_options_e = 4;
pub const SSH_OPTIONS_SSH_DIR: ssh_options_e = 5;
pub const SSH_OPTIONS_IDENTITY: ssh_options_e = 6;
pub const SSH_OPTIONS_ADD_IDENTITY: ssh_options_e = 7;
pub const SSH_OPTIONS_KNOWNHOSTS: ssh_options_e = 8;
pub const SSH_OPTIONS_TIMEOUT: ssh_options_e = 9;
pub const SSH_OPTIONS_TIMEOUT_USEC: ssh_options_e = 10;
pub const SSH_OPTIONS_SSH1: ssh_options_e = 11;
pub const SSH_OPTIONS_SSH2: ssh_options_e = 12;
pub const SSH_OPTIONS_LOG_VERBOSITY: ssh_options_e = 13;
pub const SSH_OPTIONS_LOG_VERBOSITY_STR: ssh_options_e = 14;
pub const SSH_OPTIONS_CIPHERS_C_S: ssh_options_e = 15;
pub const SSH_OPTIONS_CIPHERS_S_C: ssh_options_e = 16;
pub const SSH_OPTIONS_COMPRESSION_C_S: ssh_options_e = 17;
pub const SSH_OPTIONS_COMPRESSION_S_C: ssh_options_e = 18;
pub const SSH_OPTIONS_PROXYCOMMAND: ssh_options_e = 19;
pub const SSH_OPTIONS_BINDADDR: ssh_options_e = 20;
pub const SSH_OPTIONS_STRICTHOSTKEYCHECK: ssh_options_e = 21;
pub const SSH_OPTIONS_COMPRESSION: ssh_options_e = 22;
pub const SSH_OPTIONS_COMPRESSION_LEVEL: ssh_options_e = 23;
pub const SSH_OPTIONS_KEY_EXCHANGE: ssh_options_e = 24;
pub const SSH_OPTIONS_HOSTKEYS: ssh_options_e = 25;
pub const SSH_OPTIONS_GSSAPI_SERVER_IDENTITY: ssh_options_e = 26;
pub const SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY: ssh_options_e = 27;
pub const SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS: ssh_options_e = 28;
pub const SSH_OPTIONS_HMAC_C_S: ssh_options_e = 29;
pub const SSH_OPTIONS_HMAC_S_C: ssh_options_e = 30;
pub const SSH_OPTIONS_PASSWORD_AUTH: ssh_options_e = 31;
pub const SSH_OPTIONS_PUBKEY_AUTH: ssh_options_e = 32;
pub const SSH_OPTIONS_KBDINT_AUTH: ssh_options_e = 33;
pub const SSH_OPTIONS_GSSAPI_AUTH: ssh_options_e = 34;
pub const SSH_OPTIONS_GLOBAL_KNOWNHOSTS: ssh_options_e = 35;
pub const SSH_OPTIONS_NODELAY: ssh_options_e = 36;
pub const SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES: ssh_options_e = 37;
pub const SSH_OPTIONS_PROCESS_CONFIG: ssh_options_e = 38;
pub const SSH_OPTIONS_REKEY_DATA: ssh_options_e = 39;
pub const SSH_OPTIONS_REKEY_TIME: ssh_options_e = 40;
pub const SSH_OPTIONS_RSA_MIN_SIZE: ssh_options_e = 41;
pub const SSH_OPTIONS_IDENTITY_AGENT: ssh_options_e = 42;
pub const SSH_OPTIONS_IDENTITIES_ONLY: ssh_options_e = 43;
pub const SSH_OPTIONS_CONTROL_MASTER: ssh_options_e = 44;
pub const SSH_OPTIONS_CONTROL_PATH: ssh_options_e = 45;

pub type ssh_scp_request_types = c_int;
pub const SSH_SCP_REQUEST_NEWDIR: ssh_scp_request_types = 1;
pub const SSH_SCP_REQUEST_NEWFILE: ssh_scp_request_types = 2;
pub const SSH_SCP_REQUEST_EOF: ssh_scp_request_types = 3;
pub const SSH_SCP_REQUEST_ENDDIR: ssh_scp_request_types = 4;
pub const SSH_SCP_REQUEST_WARNING: ssh_scp_request_types = 5;

pub type ssh_connector_flags_e = c_int;
pub const SSH_CONNECTOR_STDOUT: ssh_connector_flags_e = 1;
pub const SSH_CONNECTOR_STDINOUT: ssh_connector_flags_e = 1;
pub const SSH_CONNECTOR_STDERR: ssh_connector_flags_e = 2;
pub const SSH_CONNECTOR_BOTH: ssh_connector_flags_e = 3;

pub type ssh_publickey_hash_type = c_int;
pub const SSH_PUBLICKEY_HASH_SHA1: ssh_publickey_hash_type = 0;
pub const SSH_PUBLICKEY_HASH_MD5: ssh_publickey_hash_type = 1;
pub const SSH_PUBLICKEY_HASH_SHA256: ssh_publickey_hash_type = 2;

pub type ssh_auth_callback = Option<
    unsafe extern "C" fn(
        prompt: *const c_char,
        buf: *mut c_char,
        len: usize,
        echo: c_int,
        verify: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_event_callback =
    Option<unsafe extern "C" fn(fd: socket_t, revents: c_int, userdata: *mut c_void) -> c_int>;

pub enum ssh_private_key_struct {}
pub type ssh_private_key = *mut ssh_private_key_struct;

pub enum ssh_public_key_struct {}
pub type ssh_public_key = *mut ssh_public_key_struct;

pub type ssh_callback_int = Option<unsafe extern "C" fn(code: c_int, user: *mut c_void)>;
pub type ssh_callback_data =
    Option<unsafe extern "C" fn(data: *const c_void, len: usize, user: *mut c_void) -> usize>;
pub type ssh_callback_int_int =
    Option<unsafe extern "C" fn(code: c_int, errno_code: c_int, user: *mut c_void)>;
pub type ssh_message_callback = Option<
    unsafe extern "C" fn(arg1: ssh_session, message: ssh_message, user: *mut c_void) -> c_int,
>;
pub type ssh_channel_callback_int =
    Option<unsafe extern "C" fn(channel: ssh_channel, code: c_int, user: *mut c_void) -> c_int>;
pub type ssh_channel_callback_data = Option<
    unsafe extern "C" fn(
        channel: ssh_channel,
        code: c_int,
        data: *mut c_void,
        len: usize,
        user: *mut c_void,
    ) -> c_int,
>;
pub type ssh_log_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        priority: c_int,
        message: *const c_char,
        userdata: *mut c_void,
    ),
>;
pub type ssh_logging_callback = Option<
    unsafe extern "C" fn(
        priority: c_int,
        function: *const c_char,
        buffer: *const c_char,
        userdata: *mut c_void,
    ),
>;
pub type ssh_status_callback =
    Option<unsafe extern "C" fn(session: ssh_session, status: f32, userdata: *mut c_void)>;
pub type ssh_global_request_callback =
    Option<unsafe extern "C" fn(session: ssh_session, message: ssh_message, userdata: *mut c_void)>;
pub type ssh_channel_open_request_x11_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        originator_address: *const c_char,
        originator_port: c_int,
        userdata: *mut c_void,
    ) -> ssh_channel,
>;
pub type ssh_channel_open_request_auth_agent_callback =
    Option<unsafe extern "C" fn(session: ssh_session, userdata: *mut c_void) -> ssh_channel>;
pub type ssh_channel_open_request_forwarded_tcpip_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        destination_address: *const c_char,
        destination_port: c_int,
        originator_address: *const c_char,
        originator_port: c_int,
        userdata: *mut c_void,
    ) -> ssh_channel,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_callbacks_struct {
    pub size: usize,
    pub userdata: *mut c_void,
    pub auth_function: ssh_auth_callback,
    pub log_function: ssh_log_callback,
    pub connect_status_function: Option<unsafe extern "C" fn(userdata: *mut c_void, status: f32)>,
    pub global_request_function: ssh_global_request_callback,
    pub channel_open_request_x11_function: ssh_channel_open_request_x11_callback,
    pub channel_open_request_auth_agent_function: ssh_channel_open_request_auth_agent_callback,
    pub channel_open_request_forwarded_tcpip_function:
        ssh_channel_open_request_forwarded_tcpip_callback,
}

pub type ssh_callbacks = *mut ssh_callbacks_struct;
pub type ssh_auth_password_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        user: *const c_char,
        password: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_auth_none_callback = Option<
    unsafe extern "C" fn(session: ssh_session, user: *const c_char, userdata: *mut c_void) -> c_int,
>;
pub type ssh_auth_gssapi_mic_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        user: *const c_char,
        principal: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_auth_pubkey_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        user: *const c_char,
        pubkey: *mut ssh_key_struct,
        signature_state: c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_service_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        service: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_open_request_session_callback =
    Option<unsafe extern "C" fn(session: ssh_session, userdata: *mut c_void) -> ssh_channel>;
pub type ssh_gssapi_select_oid_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        user: *const c_char,
        n_oid: c_int,
        oids: *mut ssh_string,
        userdata: *mut c_void,
    ) -> ssh_string,
>;
pub type ssh_gssapi_accept_sec_ctx_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        input_token: ssh_string,
        output_token: *mut ssh_string,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_gssapi_verify_mic_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        mic: ssh_string,
        mic_buffer: *mut c_void,
        mic_buffer_size: usize,
        userdata: *mut c_void,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_server_callbacks_struct {
    pub size: usize,
    pub userdata: *mut c_void,
    pub auth_password_function: ssh_auth_password_callback,
    pub auth_none_function: ssh_auth_none_callback,
    pub auth_gssapi_mic_function: ssh_auth_gssapi_mic_callback,
    pub auth_pubkey_function: ssh_auth_pubkey_callback,
    pub service_request_function: ssh_service_request_callback,
    pub channel_open_request_session_function: ssh_channel_open_request_session_callback,
    pub gssapi_select_oid_function: ssh_gssapi_select_oid_callback,
    pub gssapi_accept_sec_ctx_function: ssh_gssapi_accept_sec_ctx_callback,
    pub gssapi_verify_mic_function: ssh_gssapi_verify_mic_callback,
}

pub type ssh_server_callbacks = *mut ssh_server_callbacks_struct;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_socket_callbacks_struct {
    pub userdata: *mut c_void,
    pub data: ssh_callback_data,
    pub controlflow: ssh_callback_int,
    pub exception: ssh_callback_int_int,
    pub connected: ssh_callback_int_int,
}

pub type ssh_socket_callbacks = *mut ssh_socket_callbacks_struct;
pub type ssh_packet_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        type_: u8,
        packet: ssh_buffer,
        user: *mut c_void,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_packet_callbacks_struct {
    pub start: u8,
    pub n_callbacks: u8,
    pub callbacks: *mut ssh_packet_callback,
    pub user: *mut c_void,
}

pub type ssh_packet_callbacks = *mut ssh_packet_callbacks_struct;
pub type ssh_channel_data_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        data: *mut c_void,
        len: u32,
        is_stderr: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_eof_callback =
    Option<unsafe extern "C" fn(session: ssh_session, channel: ssh_channel, userdata: *mut c_void)>;
pub type ssh_channel_close_callback =
    Option<unsafe extern "C" fn(session: ssh_session, channel: ssh_channel, userdata: *mut c_void)>;
pub type ssh_channel_signal_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        signal: *const c_char,
        userdata: *mut c_void,
    ),
>;
pub type ssh_channel_exit_status_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        exit_status: c_int,
        userdata: *mut c_void,
    ),
>;
pub type ssh_channel_exit_signal_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        signal: *const c_char,
        core: c_int,
        errmsg: *const c_char,
        lang: *const c_char,
        userdata: *mut c_void,
    ),
>;
pub type ssh_channel_pty_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        term: *const c_char,
        width: c_int,
        height: c_int,
        pxwidth: c_int,
        pwheight: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_shell_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_auth_agent_req_callback =
    Option<unsafe extern "C" fn(session: ssh_session, channel: ssh_channel, userdata: *mut c_void)>;
pub type ssh_channel_x11_req_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        single_connection: c_int,
        auth_protocol: *const c_char,
        auth_cookie: *const c_char,
        screen_number: u32,
        userdata: *mut c_void,
    ),
>;
pub type ssh_channel_pty_window_change_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        width: c_int,
        height: c_int,
        pxwidth: c_int,
        pwheight: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_exec_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        command: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_env_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        env_name: *const c_char,
        env_value: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_subsystem_request_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        subsystem: *const c_char,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_write_wontblock_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        bytes: u32,
        userdata: *mut c_void,
    ) -> c_int,
>;
pub type ssh_channel_open_resp_callback = Option<
    unsafe extern "C" fn(
        session: ssh_session,
        channel: ssh_channel,
        is_success: bool,
        userdata: *mut c_void,
    ),
>;
pub type ssh_channel_request_resp_callback =
    Option<unsafe extern "C" fn(session: ssh_session, channel: ssh_channel, userdata: *mut c_void)>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_channel_callbacks_struct {
    pub size: usize,
    pub userdata: *mut c_void,
    pub channel_data_function: ssh_channel_data_callback,
    pub channel_eof_function: ssh_channel_eof_callback,
    pub channel_close_function: ssh_channel_close_callback,
    pub channel_signal_function: ssh_channel_signal_callback,
    pub channel_exit_status_function: ssh_channel_exit_status_callback,
    pub channel_exit_signal_function: ssh_channel_exit_signal_callback,
    pub channel_pty_request_function: ssh_channel_pty_request_callback,
    pub channel_shell_request_function: ssh_channel_shell_request_callback,
    pub channel_auth_agent_req_function: ssh_channel_auth_agent_req_callback,
    pub channel_x11_req_function: ssh_channel_x11_req_callback,
    pub channel_pty_window_change_function: ssh_channel_pty_window_change_callback,
    pub channel_exec_request_function: ssh_channel_exec_request_callback,
    pub channel_env_request_function: ssh_channel_env_request_callback,
    pub channel_subsystem_request_function: ssh_channel_subsystem_request_callback,
    pub channel_write_wontblock_function: ssh_channel_write_wontblock_callback,
    pub channel_open_response_function: ssh_channel_open_resp_callback,
    pub channel_request_response_function: ssh_channel_request_resp_callback,
}

pub type ssh_channel_callbacks = *mut ssh_channel_callbacks_struct;
pub type ssh_thread_callback = Option<unsafe extern "C" fn(lock: *mut *mut c_void) -> c_int>;
pub type ssh_thread_id_callback = Option<unsafe extern "C" fn() -> c_ulong>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ssh_threads_callbacks_struct {
    pub type_: *const c_char,
    pub mutex_init: ssh_thread_callback,
    pub mutex_destroy: ssh_thread_callback,
    pub mutex_lock: ssh_thread_callback,
    pub mutex_unlock: ssh_thread_callback,
    pub thread_id: ssh_thread_id_callback,
}

pub type sftp_attributes = *mut sftp_attributes_struct;
pub type sftp_client_message = *mut sftp_client_message_struct;
pub type sftp_dir = *mut sftp_dir_struct;

pub enum sftp_ext_struct {}
pub type sftp_ext = *mut sftp_ext_struct;

pub type sftp_file = *mut sftp_file_struct;
pub type sftp_message = *mut sftp_message_struct;
pub type sftp_packet = *mut sftp_packet_struct;
pub type sftp_request_queue = *mut sftp_request_queue_struct;
pub type sftp_session = *mut sftp_session_struct;
pub type sftp_status_message = *mut sftp_status_message_struct;
pub type sftp_statvfs_t = *mut sftp_statvfs_struct;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_session_struct {
    pub session: ssh_session,
    pub channel: ssh_channel,
    pub server_version: c_int,
    pub client_version: c_int,
    pub version: c_int,
    pub queue: sftp_request_queue,
    pub id_counter: u32,
    pub errnum: c_int,
    pub handles: *mut *mut c_void,
    pub ext: sftp_ext,
    pub read_packet: sftp_packet,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_packet_struct {
    pub sftp: sftp_session,
    pub type_: u8,
    pub payload: ssh_buffer,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_file_struct {
    pub sftp: sftp_session,
    pub name: *mut c_char,
    pub offset: u64,
    pub handle: ssh_string,
    pub eof: c_int,
    pub nonblocking: c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_dir_struct {
    pub sftp: sftp_session,
    pub name: *mut c_char,
    pub handle: ssh_string,
    pub buffer: ssh_buffer,
    pub count: u32,
    pub eof: c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_message_struct {
    pub sftp: sftp_session,
    pub packet_type: u8,
    pub payload: ssh_buffer,
    pub id: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_client_message_struct {
    pub sftp: sftp_session,
    pub type_: u8,
    pub id: u32,
    pub filename: *mut c_char,
    pub flags: u32,
    pub attr: sftp_attributes,
    pub handle: ssh_string,
    pub offset: u64,
    pub len: u32,
    pub attr_num: c_int,
    pub attrbuf: ssh_buffer,
    pub data: ssh_string,
    pub complete_message: ssh_buffer,
    pub str_data: *mut c_char,
    pub submessage: *mut c_char,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_request_queue_struct {
    pub next: sftp_request_queue,
    pub message: sftp_message,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_status_message_struct {
    pub id: u32,
    pub status: u32,
    pub error_unused: ssh_string,
    pub lang_unused: ssh_string,
    pub errormsg: *mut c_char,
    pub langmsg: *mut c_char,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_attributes_struct {
    pub name: *mut c_char,
    pub longname: *mut c_char,
    pub flags: u32,
    pub type_: u8,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub owner: *mut c_char,
    pub group: *mut c_char,
    pub permissions: u32,
    pub atime64: u64,
    pub atime: u32,
    pub atime_nseconds: u32,
    pub createtime: u64,
    pub createtime_nseconds: u32,
    pub mtime64: u64,
    pub mtime: u32,
    pub mtime_nseconds: u32,
    pub acl: ssh_string,
    pub extended_count: u32,
    pub extended_type: ssh_string,
    pub extended_data: ssh_string,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sftp_statvfs_struct {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
}

extern "C" {
    pub fn ssh_blocking_flush(session: ssh_session, timeout: c_int) -> c_int;
    pub fn ssh_channel_accept_x11(channel: ssh_channel, timeout_ms: c_int) -> ssh_channel;
    pub fn ssh_channel_change_pty_size(channel: ssh_channel, cols: c_int, rows: c_int) -> c_int;
    pub fn ssh_channel_close(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_free(channel: ssh_channel);
    pub fn ssh_channel_get_exit_status(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_get_session(channel: ssh_channel) -> ssh_session;
    pub fn ssh_channel_is_closed(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_is_eof(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_is_open(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_new(session: ssh_session) -> ssh_channel;
    pub fn ssh_channel_open_auth_agent(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_open_forward(
        channel: ssh_channel,
        remotehost: *const c_char,
        remoteport: c_int,
        sourcehost: *const c_char,
        localport: c_int,
    ) -> c_int;
    pub fn ssh_channel_open_forward_unix(
        channel: ssh_channel,
        remotepath: *const c_char,
        sourcehost: *const c_char,
        localport: c_int,
    ) -> c_int;
    pub fn ssh_channel_open_session(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_open_x11(
        channel: ssh_channel,
        orig_addr: *const c_char,
        orig_port: c_int,
    ) -> c_int;
    pub fn ssh_channel_poll(channel: ssh_channel, is_stderr: c_int) -> c_int;
    pub fn ssh_channel_poll_timeout(
        channel: ssh_channel,
        timeout: c_int,
        is_stderr: c_int,
    ) -> c_int;
    pub fn ssh_channel_read(
        channel: ssh_channel,
        dest: *mut c_void,
        count: u32,
        is_stderr: c_int,
    ) -> c_int;
    pub fn ssh_channel_read_timeout(
        channel: ssh_channel,
        dest: *mut c_void,
        count: u32,
        is_stderr: c_int,
        timeout_ms: c_int,
    ) -> c_int;
    pub fn ssh_channel_read_nonblocking(
        channel: ssh_channel,
        dest: *mut c_void,
        count: u32,
        is_stderr: c_int,
    ) -> c_int;
    pub fn ssh_channel_request_env(
        channel: ssh_channel,
        name: *const c_char,
        value: *const c_char,
    ) -> c_int;
    pub fn ssh_channel_request_exec(channel: ssh_channel, cmd: *const c_char) -> c_int;
    pub fn ssh_channel_request_pty(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_request_pty_size(
        channel: ssh_channel,
        term: *const c_char,
        cols: c_int,
        rows: c_int,
    ) -> c_int;
    pub fn ssh_channel_request_shell(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_request_send_signal(channel: ssh_channel, signum: *const c_char) -> c_int;
    pub fn ssh_channel_request_send_break(channel: ssh_channel, length: u32) -> c_int;
    pub fn ssh_channel_request_sftp(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_request_subsystem(channel: ssh_channel, subsystem: *const c_char) -> c_int;
    pub fn ssh_channel_request_x11(
        channel: ssh_channel,
        single_connection: c_int,
        protocol: *const c_char,
        cookie: *const c_char,
        screen_number: c_int,
    ) -> c_int;
    pub fn ssh_channel_request_auth_agent(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_send_eof(channel: ssh_channel) -> c_int;
    pub fn ssh_channel_set_blocking(channel: ssh_channel, blocking: c_int);
    pub fn ssh_channel_set_counter(channel: ssh_channel, counter: ssh_counter);
    pub fn ssh_channel_write(channel: ssh_channel, data: *const c_void, len: u32) -> c_int;
    pub fn ssh_channel_write_stderr(channel: ssh_channel, data: *const c_void, len: u32) -> c_int;
    pub fn ssh_channel_window_size(channel: ssh_channel) -> u32;
    pub fn ssh_basename(path: *const c_char) -> *mut c_char;
    pub fn ssh_clean_pubkey_hash(hash: *mut *mut c_uchar);
    pub fn ssh_connect(session: ssh_session) -> c_int;
    pub fn ssh_connector_new(session: ssh_session) -> ssh_connector;
    pub fn ssh_connector_free(connector: ssh_connector);
    pub fn ssh_connector_set_in_channel(
        connector: ssh_connector,
        channel: ssh_channel,
        flags: ssh_connector_flags_e,
    ) -> c_int;
    pub fn ssh_connector_set_out_channel(
        connector: ssh_connector,
        channel: ssh_channel,
        flags: ssh_connector_flags_e,
    ) -> c_int;
    pub fn ssh_connector_set_in_fd(connector: ssh_connector, fd: socket_t);
    pub fn ssh_connector_set_out_fd(connector: ssh_connector, fd: socket_t);
    pub fn ssh_copyright() -> *const c_char;
    pub fn ssh_disconnect(session: ssh_session);
    pub fn ssh_dirname(path: *const c_char) -> *mut c_char;
    pub fn ssh_finalize() -> c_int;
    pub fn ssh_channel_open_forward_port(
        session: ssh_session,
        timeout_ms: c_int,
        destination_port: *mut c_int,
        originator: *mut *mut c_char,
        originator_port: *mut c_int,
    ) -> ssh_channel;
    pub fn ssh_channel_accept_forward(
        session: ssh_session,
        timeout_ms: c_int,
        destination_port: *mut c_int,
    ) -> ssh_channel;
    pub fn ssh_channel_cancel_forward(
        session: ssh_session,
        address: *const c_char,
        port: c_int,
    ) -> c_int;
    pub fn ssh_channel_listen_forward(
        session: ssh_session,
        address: *const c_char,
        port: c_int,
        bound_port: *mut c_int,
    ) -> c_int;
    pub fn ssh_free(session: ssh_session);
    pub fn ssh_get_disconnect_message(session: ssh_session) -> *const c_char;
    pub fn ssh_get_error(error: *mut c_void) -> *const c_char;
    pub fn ssh_get_error_code(error: *mut c_void) -> c_int;
    pub fn ssh_get_fd(session: ssh_session) -> socket_t;
    pub fn ssh_get_hexa(what: *const c_uchar, len: usize) -> *mut c_char;
    pub fn ssh_get_issue_banner(session: ssh_session) -> *mut c_char;
    pub fn ssh_get_openssh_version(session: ssh_session) -> c_int;
    pub fn ssh_request_no_more_sessions(session: ssh_session) -> c_int;
    pub fn ssh_get_server_publickey(session: ssh_session, key: *mut ssh_key) -> c_int;
    pub fn ssh_get_publickey_hash(
        key: ssh_key,
        type_: ssh_publickey_hash_type,
        hash: *mut *mut c_uchar,
        hlen: *mut usize,
    ) -> c_int;
    pub fn ssh_get_pubkey_hash(session: ssh_session, hash: *mut *mut c_uchar) -> c_int;
    pub fn ssh_forward_accept(session: ssh_session, timeout_ms: c_int) -> ssh_channel;
    pub fn ssh_forward_cancel(session: ssh_session, address: *const c_char, port: c_int) -> c_int;
    pub fn ssh_forward_listen(
        session: ssh_session,
        address: *const c_char,
        port: c_int,
        bound_port: *mut c_int,
    ) -> c_int;
    pub fn ssh_get_publickey(session: ssh_session, key: *mut ssh_key) -> c_int;
    pub fn ssh_write_knownhost(session: ssh_session) -> c_int;
    pub fn ssh_dump_knownhost(session: ssh_session) -> *mut c_char;
    pub fn ssh_is_server_known(session: ssh_session) -> c_int;
    pub fn ssh_print_hexa(descr: *const c_char, what: *const c_uchar, len: usize);
    pub fn ssh_channel_select(
        readchans: *mut ssh_channel,
        writechans: *mut ssh_channel,
        exceptchans: *mut ssh_channel,
        timeout: *mut timeval,
    ) -> c_int;
    pub fn ssh_scp_accept_request(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_close(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_deny_request(scp: ssh_scp, reason: *const c_char) -> c_int;
    pub fn ssh_scp_free(scp: ssh_scp);
    pub fn ssh_scp_init(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_leave_directory(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_new(session: ssh_session, mode: c_int, location: *const c_char) -> ssh_scp;
    pub fn ssh_scp_pull_request(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_push_directory(scp: ssh_scp, dirname: *const c_char, mode: c_int) -> c_int;
    pub fn ssh_scp_push_file(
        scp: ssh_scp,
        filename: *const c_char,
        size: usize,
        perms: c_int,
    ) -> c_int;
    pub fn ssh_scp_push_file64(
        scp: ssh_scp,
        filename: *const c_char,
        size: u64,
        perms: c_int,
    ) -> c_int;
    pub fn ssh_scp_read(scp: ssh_scp, buffer: *mut c_void, size: usize) -> c_int;
    pub fn ssh_scp_request_get_filename(scp: ssh_scp) -> *const c_char;
    pub fn ssh_scp_request_get_permissions(scp: ssh_scp) -> c_int;
    pub fn ssh_scp_request_get_size(scp: ssh_scp) -> usize;
    pub fn ssh_scp_request_get_size64(scp: ssh_scp) -> u64;
    pub fn ssh_scp_request_get_warning(scp: ssh_scp) -> *const c_char;
    pub fn ssh_scp_write(scp: ssh_scp, buffer: *const c_void, len: usize) -> c_int;
    pub fn ssh_get_random(where_: *mut c_void, len: c_int, strong: c_int) -> c_int;
    pub fn ssh_get_version(session: ssh_session) -> c_int;
    pub fn ssh_get_status(session: ssh_session) -> c_int;
    pub fn ssh_get_poll_flags(session: ssh_session) -> c_int;
    pub fn ssh_init() -> c_int;
    pub fn ssh_is_blocking(session: ssh_session) -> c_int;
    pub fn ssh_is_connected(session: ssh_session) -> c_int;
    pub fn ssh_knownhosts_entry_free(entry: *mut ssh_knownhosts_entry);
    pub fn ssh_known_hosts_parse_line(
        host: *const c_char,
        line: *const c_char,
        entry: *mut *mut ssh_knownhosts_entry,
    ) -> c_int;
    pub fn ssh_session_has_known_hosts_entry(session: ssh_session) -> ssh_known_hosts_e;
    pub fn ssh_session_export_known_hosts_entry(
        session: ssh_session,
        pentry_string: *mut *mut c_char,
    ) -> c_int;
    pub fn ssh_session_update_known_hosts(session: ssh_session) -> c_int;
    pub fn ssh_session_get_known_hosts_entry(
        session: ssh_session,
        pentry: *mut *mut ssh_knownhosts_entry,
    ) -> ssh_known_hosts_e;
    pub fn ssh_session_is_known_server(session: ssh_session) -> ssh_known_hosts_e;
    pub fn ssh_set_log_level(level: c_int) -> c_int;
    pub fn ssh_get_log_level() -> c_int;
    pub fn ssh_get_log_userdata() -> *mut c_void;
    pub fn ssh_set_log_userdata(data: *mut c_void) -> c_int;
    pub fn ssh_log(session: ssh_session, prioriry: c_int, format: *const c_char, ...);
    pub fn ssh_message_channel_request_open_reply_accept(msg: ssh_message) -> ssh_channel;
    pub fn ssh_message_channel_request_open_reply_accept_channel(
        msg: ssh_message,
        chan: ssh_channel,
    ) -> c_int;
    pub fn ssh_message_channel_request_reply_success(msg: ssh_message) -> c_int;
    pub fn ssh_message_free(msg: ssh_message);
    pub fn ssh_message_get(session: ssh_session) -> ssh_message;
    pub fn ssh_message_subtype(msg: ssh_message) -> c_int;
    pub fn ssh_message_type(msg: ssh_message) -> c_int;
    pub fn ssh_mkdir(pathname: *const c_char, mode: c_int) -> c_int;
    pub fn ssh_new() -> ssh_session;
    pub fn ssh_options_copy(src: ssh_session, dest: *mut ssh_session) -> c_int;
    pub fn ssh_options_getopt(
        session: ssh_session,
        argcptr: *mut c_int,
        argv: *mut *mut c_char,
    ) -> c_int;
    pub fn ssh_options_parse_config(session: ssh_session, filename: *const c_char) -> c_int;
    pub fn ssh_options_set(
        session: ssh_session,
        type_: ssh_options_e,
        value: *const c_void,
    ) -> c_int;
    pub fn ssh_options_get(
        session: ssh_session,
        type_: ssh_options_e,
        value: *mut *mut c_char,
    ) -> c_int;
    pub fn ssh_options_get_port(session: ssh_session, port_target: *mut c_uint) -> c_int;
    pub fn ssh_pcap_file_close(pcap: ssh_pcap_file) -> c_int;
    pub fn ssh_pcap_file_free(pcap: ssh_pcap_file);
    pub fn ssh_pcap_file_new() -> ssh_pcap_file;
    pub fn ssh_pcap_file_open(pcap: ssh_pcap_file, filename: *const c_char) -> c_int;
    pub fn ssh_key_new() -> ssh_key;
    pub fn ssh_key_free(key: ssh_key);
    pub fn ssh_key_type(key: ssh_key) -> ssh_keytypes_e;
    pub fn ssh_key_type_to_char(type_: ssh_keytypes_e) -> *const c_char;
    pub fn ssh_key_type_from_name(name: *const c_char) -> ssh_keytypes_e;
    pub fn ssh_key_is_public(k: ssh_key) -> c_int;
    pub fn ssh_key_is_private(k: ssh_key) -> c_int;
    pub fn ssh_key_cmp(k1: ssh_key, k2: ssh_key, what: ssh_keycmp_e) -> c_int;
    pub fn ssh_key_dup(key: ssh_key) -> ssh_key;
    pub fn ssh_pki_generate(type_: ssh_keytypes_e, parameter: c_int, pkey: *mut ssh_key) -> c_int;
    pub fn ssh_pki_import_privkey_base64(
        b64_key: *const c_char,
        passphrase: *const c_char,
        auth_fn: ssh_auth_callback,
        auth_data: *mut c_void,
        pkey: *mut ssh_key,
    ) -> c_int;
    pub fn ssh_pki_export_privkey_base64(
        privkey: ssh_key,
        passphrase: *const c_char,
        auth_fn: ssh_auth_callback,
        auth_data: *mut c_void,
        b64_key: *mut *mut c_char,
    ) -> c_int;
    pub fn ssh_pki_import_privkey_file(
        filename: *const c_char,
        passphrase: *const c_char,
        auth_fn: ssh_auth_callback,
        auth_data: *mut c_void,
        pkey: *mut ssh_key,
    ) -> c_int;
    pub fn ssh_pki_export_privkey_file(
        privkey: ssh_key,
        passphrase: *const c_char,
        auth_fn: ssh_auth_callback,
        auth_data: *mut c_void,
        filename: *const c_char,
    ) -> c_int;
    pub fn ssh_pki_copy_cert_to_privkey(cert_key: ssh_key, privkey: ssh_key) -> c_int;
    pub fn ssh_pki_import_pubkey_base64(
        b64_key: *const c_char,
        type_: ssh_keytypes_e,
        pkey: *mut ssh_key,
    ) -> c_int;
    pub fn ssh_pki_import_pubkey_file(filename: *const c_char, pkey: *mut ssh_key) -> c_int;
    pub fn ssh_pki_import_cert_base64(
        b64_cert: *const c_char,
        type_: ssh_keytypes_e,
        pkey: *mut ssh_key,
    ) -> c_int;
    pub fn ssh_pki_import_cert_file(filename: *const c_char, pkey: *mut ssh_key) -> c_int;
    pub fn ssh_pki_export_privkey_to_pubkey(privkey: ssh_key, pkey: *mut ssh_key) -> c_int;
    pub fn ssh_pki_export_pubkey_base64(key: ssh_key, b64_key: *mut *mut c_char) -> c_int;
    pub fn ssh_pki_export_pubkey_file(key: ssh_key, filename: *const c_char) -> c_int;
    pub fn ssh_pki_key_ecdsa_name(key: ssh_key) -> *const c_char;
    pub fn ssh_get_fingerprint_hash(
        type_: ssh_publickey_hash_type,
        hash: *mut c_uchar,
        len: usize,
    ) -> *mut c_char;
    pub fn ssh_print_hash(type_: ssh_publickey_hash_type, hash: *mut c_uchar, len: usize);
    pub fn ssh_send_ignore(session: ssh_session, data: *const c_char) -> c_int;
    pub fn ssh_send_debug(
        session: ssh_session,
        message: *const c_char,
        always_display: c_int,
    ) -> c_int;
    pub fn ssh_gssapi_set_creds(session: ssh_session, creds: ssh_gssapi_creds);
    pub fn ssh_select(
        channels: *mut ssh_channel,
        outchannels: *mut ssh_channel,
        maxfd: socket_t,
        readfds: *mut fd_set,
        timeout: *mut timeval,
    ) -> c_int;
    pub fn ssh_service_request(session: ssh_session, service: *const c_char) -> c_int;
    pub fn ssh_set_agent_channel(session: ssh_session, channel: ssh_channel) -> c_int;
    pub fn ssh_set_agent_socket(session: ssh_session, fd: socket_t) -> c_int;
    pub fn ssh_set_blocking(session: ssh_session, blocking: c_int);
    pub fn ssh_set_counters(session: ssh_session, scounter: ssh_counter, rcounter: ssh_counter);
    pub fn ssh_set_fd_except(session: ssh_session);
    pub fn ssh_set_fd_toread(session: ssh_session);
    pub fn ssh_set_fd_towrite(session: ssh_session);
    pub fn ssh_silent_disconnect(session: ssh_session);
    pub fn ssh_set_pcap_file(session: ssh_session, pcapfile: ssh_pcap_file) -> c_int;
    pub fn ssh_userauth_none(session: ssh_session, username: *const c_char) -> c_int;
    pub fn ssh_userauth_list(session: ssh_session, username: *const c_char) -> c_int;
    pub fn ssh_userauth_try_publickey(
        session: ssh_session,
        username: *const c_char,
        pubkey: ssh_key,
    ) -> c_int;
    pub fn ssh_userauth_publickey(
        session: ssh_session,
        username: *const c_char,
        privkey: ssh_key,
    ) -> c_int;
    pub fn ssh_userauth_publickey_auto_get_current_identity(
        session: ssh_session,
        value: *mut *mut c_char,
    ) -> c_int;
    pub fn ssh_userauth_publickey_auto(
        session: ssh_session,
        username: *const c_char,
        passphrase: *const c_char,
    ) -> c_int;
    pub fn ssh_userauth_password(
        session: ssh_session,
        username: *const c_char,
        password: *const c_char,
    ) -> c_int;
    pub fn ssh_userauth_kbdint(
        session: ssh_session,
        user: *const c_char,
        submethods: *const c_char,
    ) -> c_int;
    pub fn ssh_userauth_kbdint_getinstruction(session: ssh_session) -> *const c_char;
    pub fn ssh_userauth_kbdint_getname(session: ssh_session) -> *const c_char;
    pub fn ssh_userauth_kbdint_getnprompts(session: ssh_session) -> c_int;
    pub fn ssh_userauth_kbdint_getprompt(
        session: ssh_session,
        i: c_uint,
        echo: *mut c_char,
    ) -> *const c_char;
    pub fn ssh_userauth_kbdint_getnanswers(session: ssh_session) -> c_int;
    pub fn ssh_userauth_kbdint_getanswer(session: ssh_session, i: c_uint) -> *const c_char;
    pub fn ssh_userauth_kbdint_setanswer(
        session: ssh_session,
        i: c_uint,
        answer: *const c_char,
    ) -> c_int;
    pub fn ssh_userauth_gssapi(session: ssh_session) -> c_int;
    pub fn ssh_version(req_version: c_int) -> *const c_char;
    pub fn ssh_string_burn(str_: ssh_string);
    pub fn ssh_string_copy(str_: ssh_string) -> ssh_string;
    pub fn ssh_string_data(str_: ssh_string) -> *mut c_void;
    pub fn ssh_string_fill(str_: ssh_string, data: *const c_void, len: usize) -> c_int;
    pub fn ssh_string_free(str_: ssh_string);
    pub fn ssh_string_from_char(what: *const c_char) -> ssh_string;
    pub fn ssh_string_len(str_: ssh_string) -> usize;
    pub fn ssh_string_new(size: usize) -> ssh_string;
    pub fn ssh_string_get_char(str_: ssh_string) -> *const c_char;
    pub fn ssh_string_to_char(str_: ssh_string) -> *mut c_char;
    pub fn ssh_string_free_char(s: *mut c_char);
    pub fn ssh_getpass(
        prompt: *const c_char,
        buf: *mut c_char,
        len: usize,
        echo: c_int,
        verify: c_int,
    ) -> c_int;
    pub fn ssh_event_new() -> ssh_event;
    pub fn ssh_event_add_fd(
        event: ssh_event,
        fd: socket_t,
        events: c_short,
        cb: ssh_event_callback,
        userdata: *mut c_void,
    ) -> c_int;
    pub fn ssh_event_add_session(event: ssh_event, session: ssh_session) -> c_int;
    pub fn ssh_event_add_connector(event: ssh_event, connector: ssh_connector) -> c_int;
    pub fn ssh_event_dopoll(event: ssh_event, timeout: c_int) -> c_int;
    pub fn ssh_event_remove_fd(event: ssh_event, fd: socket_t) -> c_int;
    pub fn ssh_event_remove_session(event: ssh_event, session: ssh_session) -> c_int;
    pub fn ssh_event_remove_connector(event: ssh_event, connector: ssh_connector) -> c_int;
    pub fn ssh_event_free(event: ssh_event);
    pub fn ssh_get_clientbanner(session: ssh_session) -> *const c_char;
    pub fn ssh_get_serverbanner(session: ssh_session) -> *const c_char;
    pub fn ssh_get_kex_algo(session: ssh_session) -> *const c_char;
    pub fn ssh_get_cipher_in(session: ssh_session) -> *const c_char;
    pub fn ssh_get_cipher_out(session: ssh_session) -> *const c_char;
    pub fn ssh_get_hmac_in(session: ssh_session) -> *const c_char;
    pub fn ssh_get_hmac_out(session: ssh_session) -> *const c_char;
    pub fn ssh_buffer_new() -> ssh_buffer;
    pub fn ssh_buffer_free(buffer: ssh_buffer);
    pub fn ssh_buffer_reinit(buffer: ssh_buffer) -> c_int;
    pub fn ssh_buffer_add_data(buffer: ssh_buffer, data: *const c_void, len: u32) -> c_int;
    pub fn ssh_buffer_get_data(buffer: ssh_buffer, data: *mut c_void, requestedlen: u32) -> u32;
    pub fn ssh_buffer_get(buffer: ssh_buffer) -> *mut c_void;
    pub fn ssh_buffer_get_len(buffer: ssh_buffer) -> u32;
    pub fn ssh_session_set_disconnect_message(
        session: ssh_session,
        message: *const c_char,
    ) -> c_int;
    pub fn ssh_auth_list(session: ssh_session) -> c_int;
    pub fn ssh_userauth_offer_pubkey(
        session: ssh_session,
        username: *const c_char,
        type_: c_int,
        publickey: ssh_string,
    ) -> c_int;
    pub fn ssh_userauth_pubkey(
        session: ssh_session,
        username: *const c_char,
        publickey: ssh_string,
        privatekey: ssh_private_key,
    ) -> c_int;
    pub fn ssh_userauth_autopubkey(session: ssh_session, passphrase: *const c_char) -> c_int;
    pub fn ssh_userauth_privatekey_file(
        session: ssh_session,
        username: *const c_char,
        filename: *const c_char,
        passphrase: *const c_char,
    ) -> c_int;
    pub fn ssh_publickey_to_file(
        session: ssh_session,
        file: *const c_char,
        pubkey: ssh_string,
        type_: c_int,
    ) -> c_int;
    pub fn ssh_try_publickey_from_file(
        session: ssh_session,
        keyfile: *const c_char,
        publickey: *mut ssh_string,
        type_: *mut c_int,
    ) -> c_int;
    pub fn ssh_privatekey_type(privatekey: ssh_private_key) -> ssh_keytypes_e;
    pub fn ssh_get_pubkey(session: ssh_session) -> ssh_string;
    pub fn ssh_message_retrieve(session: ssh_session, packettype: u32) -> ssh_message;
    pub fn ssh_message_auth_publickey(msg: ssh_message) -> ssh_public_key;
    pub fn ssh_set_server_callbacks(session: ssh_session, cb: ssh_server_callbacks) -> c_int;
    pub fn ssh_set_callbacks(session: ssh_session, cb: ssh_callbacks) -> c_int;
    pub fn ssh_set_channel_callbacks(channel: ssh_channel, cb: ssh_channel_callbacks) -> c_int;
    pub fn ssh_add_channel_callbacks(channel: ssh_channel, cb: ssh_channel_callbacks) -> c_int;
    pub fn ssh_remove_channel_callbacks(channel: ssh_channel, cb: ssh_channel_callbacks) -> c_int;
    pub fn ssh_threads_set_callbacks(cb: *mut ssh_threads_callbacks_struct) -> c_int;
    pub fn ssh_threads_get_default() -> *mut ssh_threads_callbacks_struct;
    pub fn ssh_threads_get_pthread() -> *mut ssh_threads_callbacks_struct;
    pub fn ssh_threads_get_noop() -> *mut ssh_threads_callbacks_struct;
    pub fn ssh_set_log_callback(cb: ssh_logging_callback) -> c_int;
    pub fn ssh_get_log_callback() -> ssh_logging_callback;
}

// SFTP
extern "C" {
    pub fn sftp_new(session: ssh_session) -> sftp_session;
    pub fn sftp_new_channel(session: ssh_session, channel: ssh_channel) -> sftp_session;
    pub fn sftp_free(sftp: sftp_session);
    pub fn sftp_init(sftp: sftp_session) -> c_int;
    pub fn sftp_get_error(sftp: sftp_session) -> c_int;
    pub fn sftp_extensions_get_count(sftp: sftp_session) -> c_uint;
    pub fn sftp_extensions_get_name(sftp: sftp_session, indexn: c_uint) -> *const c_char;
    pub fn sftp_extensions_get_data(sftp: sftp_session, indexn: c_uint) -> *const c_char;
    pub fn sftp_extension_supported(
        sftp: sftp_session,
        name: *const c_char,
        data: *const c_char,
    ) -> c_int;
    pub fn sftp_opendir(session: sftp_session, path: *const c_char) -> sftp_dir;
    pub fn sftp_readdir(session: sftp_session, dir: sftp_dir) -> sftp_attributes;
    pub fn sftp_dir_eof(dir: sftp_dir) -> c_int;
    pub fn sftp_stat(session: sftp_session, path: *const c_char) -> sftp_attributes;
    pub fn sftp_lstat(session: sftp_session, path: *const c_char) -> sftp_attributes;
    pub fn sftp_fstat(file: sftp_file) -> sftp_attributes;
    pub fn sftp_attributes_free(file: sftp_attributes);
    pub fn sftp_closedir(dir: sftp_dir) -> c_int;
    pub fn sftp_close(file: sftp_file) -> c_int;
    pub fn sftp_open(
        session: sftp_session,
        file: *const c_char,
        accesstype: c_int,
        mode: c_int,
    ) -> sftp_file;
    pub fn sftp_file_set_nonblocking(handle: sftp_file);
    pub fn sftp_file_set_blocking(handle: sftp_file);
    pub fn sftp_read(file: sftp_file, buf: *mut c_void, count: usize) -> isize;
    pub fn sftp_async_read_begin(file: sftp_file, len: u32) -> c_int;
    pub fn sftp_async_read(file: sftp_file, data: *mut c_void, len: u32, id: u32) -> c_int;
    pub fn sftp_write(file: sftp_file, buf: *const c_void, count: usize) -> isize;
    pub fn sftp_seek(file: sftp_file, new_offset: u32) -> c_int;
    pub fn sftp_seek64(file: sftp_file, new_offset: u64) -> c_int;
    pub fn sftp_tell(file: sftp_file) -> c_ulong;
    pub fn sftp_tell64(file: sftp_file) -> u64;
    pub fn sftp_rewind(file: sftp_file);
    pub fn sftp_unlink(sftp: sftp_session, file: *const c_char) -> c_int;
    pub fn sftp_rmdir(sftp: sftp_session, directory: *const c_char) -> c_int;
    pub fn sftp_mkdir(sftp: sftp_session, directory: *const c_char, mode: c_int) -> c_int;
    pub fn sftp_rename(
        sftp: sftp_session,
        original: *const c_char,
        newname: *const c_char,
    ) -> c_int;
    pub fn sftp_setstat(sftp: sftp_session, file: *const c_char, attr: sftp_attributes) -> c_int;
    pub fn sftp_chown(
        sftp: sftp_session,
        file: *const c_char,
        owner: c_uint,
        group: c_uint,
    ) -> c_int;
    pub fn sftp_chmod(sftp: sftp_session, file: *const c_char, mode: c_int) -> c_int;
    pub fn sftp_utimes(sftp: sftp_session, file: *const c_char, times: *const timeval) -> c_int;
    pub fn sftp_symlink(sftp: sftp_session, target: *const c_char, dest: *const c_char) -> c_int;
    pub fn sftp_readlink(sftp: sftp_session, path: *const c_char) -> *mut c_char;
    pub fn sftp_hardlink(
        sftp: sftp_session,
        oldpath: *const c_char,
        newpath: *const c_char,
    ) -> c_int;
    pub fn sftp_statvfs(sftp: sftp_session, path: *const c_char) -> sftp_statvfs_t;
    pub fn sftp_fstatvfs(file: sftp_file) -> sftp_statvfs_t;
    pub fn sftp_statvfs_free(statvfs_o: sftp_statvfs_t);
    pub fn sftp_fsync(file: sftp_file) -> c_int;
    pub fn sftp_canonicalize_path(sftp: sftp_session, path: *const c_char) -> *mut c_char;
    pub fn sftp_server_version(sftp: sftp_session) -> c_int;
    pub fn sftp_get_client_message(sftp: sftp_session) -> sftp_client_message;
    pub fn sftp_client_message_free(msg: sftp_client_message);
    pub fn sftp_client_message_get_type(msg: sftp_client_message) -> u8;
    pub fn sftp_client_message_get_filename(msg: sftp_client_message) -> *const c_char;
    pub fn sftp_client_message_set_filename(msg: sftp_client_message, newname: *const c_char);
    pub fn sftp_client_message_get_data(msg: sftp_client_message) -> *const c_char;
    pub fn sftp_client_message_get_flags(msg: sftp_client_message) -> u32;
    pub fn sftp_client_message_get_submessage(msg: sftp_client_message) -> *const c_char;
    pub fn sftp_send_client_message(sftp: sftp_session, msg: sftp_client_message) -> c_int;
    pub fn sftp_reply_name(
        msg: sftp_client_message,
        name: *const c_char,
        attr: sftp_attributes,
    ) -> c_int;
    pub fn sftp_reply_handle(msg: sftp_client_message, handle: ssh_string) -> c_int;
    pub fn sftp_handle_alloc(sftp: sftp_session, info: *mut c_void) -> ssh_string;
    pub fn sftp_reply_attr(msg: sftp_client_message, attr: sftp_attributes) -> c_int;
    pub fn sftp_handle(sftp: sftp_session, handle: ssh_string) -> *mut c_void;
    pub fn sftp_reply_status(
        msg: sftp_client_message,
        status: u32,
        message: *const c_char,
    ) -> c_int;
    pub fn sftp_reply_names_add(
        msg: sftp_client_message,
        file: *const c_char,
        longname: *const c_char,
        attr: sftp_attributes,
    ) -> c_int;
    pub fn sftp_reply_names(msg: sftp_client_message) -> c_int;
    pub fn sftp_reply_data(msg: sftp_client_message, data: *const c_void, len: c_int) -> c_int;
    pub fn sftp_handle_remove(sftp: sftp_session, handle: *mut c_void);
}
