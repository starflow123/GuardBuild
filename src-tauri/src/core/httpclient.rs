use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use native_tls::{TlsConnector, TlsStream};
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{HostError, HostResult};

pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

/// 读写通道抽象：明文 TCP 与 TLS 包装后共享同一调用面。
trait ReadWrite: Read + Write {}
impl ReadWrite for TcpStream {}
impl ReadWrite for TlsStream<TcpStream> {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub truncated: bool,
    pub duration_ms: u64,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        _ => 80,
    }
}

/// 极简 HTTP/1.1 客户端：支持明文 HTTP（回环探测）与 HTTPS（native-tls，net.egress 探测），
/// 支持 Content-Length 与 chunked 两种响应体；始终使用 Connection: close。
/// 协议/主机策略由调用方（host.rs 作用域校验）把关，这里只负责传输。
pub fn request(
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout: Duration,
) -> HostResult<HttpResponse> {
    let started = Instant::now();
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(HostError::Network(format!(
            "仅支持 http/https 协议: {scheme}"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| HostError::Network("URL 缺少主机名".into()))?
        .to_string();
    let port = url.port().unwrap_or_else(|| default_port(scheme));
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let path_and_query = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };

    // 解析地址（localhost 优先 IPv4）
    let addr: SocketAddr = if host == "localhost" {
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| HostError::Network(format!("无法解析 {host}:{port}: {e}")))?
            .next()
            .ok_or_else(|| HostError::Network(format!("无法解析 {host}:{port}")))?
    };

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| HostError::Network(format!("连接 {addr} 失败: {e}")))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| HostError::Network(e.to_string()))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| HostError::Network(e.to_string()))?;

    // https：在已连接的 TCP 上做 TLS 握手（系统根证书校验；SNI 用主机名）
    let mut stream: Box<dyn ReadWrite> = if scheme == "https" {
        let connector =
            TlsConnector::new().map_err(|e| HostError::Network(format!("TLS 初始化失败: {e}")))?;
        let tls = connector
            .connect(&host, tcp)
            .map_err(|e| HostError::Network(format!("TLS 握手失败（{host}）: {e}")))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let body_bytes = body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let mut req = String::new();
    req.push_str(&format!("{method} {path_and_query} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str("Accept: */*\r\n");
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    let mut has_content_type = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_content_type && !body_bytes.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(&body_bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| HostError::Network(format!("发送请求失败: {e}")))?;

    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE_BYTES + 64 * 1024 {
                    break;
                }
            }
            Err(e) => {
                if raw.is_empty() {
                    return Err(HostError::Network(format!("读取响应失败: {e}")));
                }
                break;
            }
        }
    }

    let header_end = find_header_end(&raw)
        .ok_or_else(|| HostError::Network("响应格式错误：未找到响应头结束标记".into()))?;
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let _http = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HostError::Network(format!("状态行解析失败: {status_line}")))?;
    let status_text = parts.next().unwrap_or("").to_string();

    let mut headers_out: Vec<(String, String)> = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers_out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body_raw = raw[header_end + 4..].to_vec();
    let chunked = headers_out
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_lowercase().contains("chunked"));
    if chunked {
        body_raw = decode_chunked(&body_raw);
    }

    let truncated = body_raw.len() > MAX_RESPONSE_BYTES;
    if truncated {
        body_raw.truncate(MAX_RESPONSE_BYTES);
    }

    Ok(HttpResponse {
        status,
        status_text,
        headers: headers_out,
        body: String::from_utf8_lossy(&body_raw).to_string(),
        truncated,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        // 读取一行 size（16 进制），允许扩展 "size;ext"
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(i) => pos + i,
            None => break,
        };
        let line = String::from_utf8_lossy(&data[pos..line_end]).to_string();
        let size_str = line.split(';').next().unwrap_or("").trim().to_string();
        let size = match usize::from_str_radix(&size_str, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = (pos + size).min(data.len());
        out.extend_from_slice(&data[pos..end]);
        pos = end + 2; // 跳过 chunk 末尾 CRLF
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;

    #[test]
    fn decodes_chunked_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body), b"hello world");
    }

    #[test]
    fn roundtrip_against_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = r#"{"ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/api/health")).unwrap();
        let r = request(&url, "GET", &[], None, Duration::from_secs(5)).unwrap();
        assert_eq!(r.status, 200);
        assert!(r.body.contains("\"ok\":true"));
    }

    /// 真实 HTTPS 冒烟（需公网）：`cargo test -- --ignored https_smoke_external`
    #[test]
    #[ignore = "需要公网访问，手动执行以验证 TLS 链路"]
    fn https_smoke_external() {
        let url = Url::parse("https://example.com/").unwrap();
        let r = request(&url, "GET", &[], None, Duration::from_secs(15)).unwrap();
        assert_eq!(r.status, 200, "status={}", r.status);
        assert!(r.body.contains("Example Domain"), "响应体未包含预期内容");
    }
}
