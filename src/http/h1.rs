use std::cmp;
use std::fmt;

use bytes::Bytes;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};

use ::http::{
    HeaderMap, HeaderName, Method, StatusCode, Uri, Version,
    header::{self, HeaderValue as HttpHeaderValue},
};

const READ_BUF_SIZE: usize = 8 * 1024;
const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_LINE_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    InvalidRequest(&'static str),
    InvalidResponse(&'static str),
    InvalidHeader,
    InvalidChunked,
    HeadersTooLarge,
    LineTooLong,
    UnexpectedEof,
    MissingIo,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Io(err) => write!(f, "io error: {err}"),
            HttpError::InvalidRequest(msg) => write!(f, "invalid request: {msg}"),
            HttpError::InvalidResponse(msg) => write!(f, "invalid response: {msg}"),
            HttpError::InvalidHeader => write!(f, "invalid header"),
            HttpError::InvalidChunked => write!(f, "invalid chunked encoding"),
            HttpError::HeadersTooLarge => write!(f, "headers too large"),
            HttpError::LineTooLong => write!(f, "line too long"),
            HttpError::UnexpectedEof => write!(f, "unexpected eof"),
            HttpError::MissingIo => write!(f, "missing io"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(value: std::io::Error) -> Self {
        HttpError::Io(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamHint {
    None,
    Fixed,
    Stream,
}

#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub tls: bool,
}

#[derive(Clone, Debug)]
pub struct ResponseHead {
    pub status: StatusCode,
    pub status_text: String,
    pub version: Version,
    pub headers: HeaderMap,
}

pub struct Request {
    head: RequestHead,
    body: Body,
}

impl Request {
    pub fn into_parts(self) -> (RequestHead, Body) {
        (self.head, self.body)
    }
}

pub struct Response {
    head: ResponseHead,
    body: Body,
}

impl Response {
    pub fn into_parts(self) -> (ResponseHead, Body) {
        (self.head, self.body)
    }
}

pub enum Body {
    None,
    Fixed {
        remaining: u64,
    },
    Chunked {
        remaining: usize,
        need_crlf: bool,
        done: bool,
    },
    Eof {
        done: bool,
    },
}

impl Body {
    pub fn hint(&self) -> StreamHint {
        match self {
            Body::None => StreamHint::None,
            Body::Fixed { .. } => StreamHint::Fixed,
            Body::Chunked { .. } | Body::Eof { .. } => StreamHint::Stream,
        }
    }

    pub fn is_chunked(&self) -> bool {
        matches!(self, Body::Chunked { .. })
    }

    pub fn is_eof(&self) -> bool {
        matches!(self, Body::Eof { .. })
    }

    pub async fn next_data<IO: AsyncReadRent>(
        &mut self,
        conn: &mut H1Connection<IO>,
    ) -> Option<Result<Bytes, HttpError>> {
        match self {
            Body::None => None,
            Body::Fixed { remaining } => {
                if *remaining == 0 {
                    return None;
                }
                let to_read = cmp::min(*remaining, READ_BUF_SIZE as u64) as usize;
                match conn.read_exact(to_read).await {
                    Ok(bytes) => {
                        *remaining -= bytes.len() as u64;
                        Some(Ok(bytes))
                    }
                    Err(err) => Some(Err(err)),
                }
            }
            Body::Chunked {
                remaining,
                need_crlf,
                done,
            } => {
                if *done {
                    return None;
                }
                if *remaining == 0 {
                    if *need_crlf {
                        if let Err(err) = conn.read_chunk_crlf().await {
                            return Some(Err(err));
                        }
                        *need_crlf = false;
                    }
                    match conn.read_chunk_size().await {
                        Ok(Some(size)) => {
                            if size == 0 {
                                if let Err(err) = conn.read_chunk_trailers().await {
                                    return Some(Err(err));
                                }
                                *done = true;
                                return None;
                            }
                            *remaining = size;
                        }
                        Ok(None) => return Some(Err(HttpError::UnexpectedEof)),
                        Err(err) => return Some(Err(err)),
                    }
                }
                let to_read = cmp::min(*remaining, READ_BUF_SIZE) as usize;
                match conn.read_exact(to_read).await {
                    Ok(bytes) => {
                        *remaining -= bytes.len();
                        if *remaining == 0 {
                            *need_crlf = true;
                        }
                        Some(Ok(bytes))
                    }
                    Err(err) => Some(Err(err)),
                }
            }
            Body::Eof { done } => {
                if *done {
                    return None;
                }
                match conn.read_some().await {
                    Ok(Some(bytes)) => Some(Ok(bytes)),
                    Ok(None) => {
                        *done = true;
                        None
                    }
                    Err(err) => Some(Err(err)),
                }
            }
        }
    }
}

pub struct H1Connection<IO> {
    io: Option<IO>,
    buf: Vec<u8>,
    pos: usize,
}

impl<IO> H1Connection<IO> {
    pub fn new(io: IO) -> Self {
        Self {
            io: Some(io),
            buf: Vec::new(),
            pos: 0,
        }
    }

    pub fn io_mut(&mut self) -> Result<&mut IO, HttpError> {
        self.io.as_mut().ok_or(HttpError::MissingIo)
    }

    pub fn io_ref(&self) -> Option<&IO> {
        self.io.as_ref()
    }

    pub fn take_io(&mut self) -> Option<(IO, Vec<u8>)> {
        let io = self.io.take()?;
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let leftover = std::mem::take(&mut self.buf);
        Some((io, leftover))
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 4096 && self.pos > self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn find_crlf(&self) -> Option<usize> {
        self.buf[self.pos..].windows(2).position(|x| x == b"\r\n")
    }

    fn find_double_crlf(&self) -> Option<usize> {
        self.buf[self.pos..]
            .windows(4)
            .position(|x| x == b"\r\n\r\n")
    }
}

impl<IO: AsyncReadRent> H1Connection<IO> {
    async fn read_more(&mut self) -> Result<usize, HttpError> {
        let io = self.io.as_mut().ok_or(HttpError::MissingIo)?;
        let buf = vec![0u8; READ_BUF_SIZE];
        let (res, buf) = io.read(buf).await;
        let n = res?;
        if n > 0 {
            self.buf.extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }

    async fn read_headers(&mut self) -> Result<Option<Vec<u8>>, HttpError> {
        loop {
            if let Some(idx) = self.find_double_crlf() {
                let start = self.pos;
                let end = self.pos + idx;
                let out = self.buf[start..end].to_vec();
                self.consume(idx + 4);
                return Ok(Some(out));
            }
            if self.buf.len().saturating_sub(self.pos) > MAX_HEADER_SIZE {
                return Err(HttpError::HeadersTooLarge);
            }
            let n = self.read_more().await?;
            if n == 0 {
                if self.buf.len() == self.pos {
                    return Ok(None);
                }
                return Err(HttpError::UnexpectedEof);
            }
        }
    }

    async fn read_line(&mut self) -> Result<Option<Vec<u8>>, HttpError> {
        loop {
            if let Some(idx) = self.find_crlf() {
                if idx > MAX_LINE_SIZE {
                    return Err(HttpError::LineTooLong);
                }
                let start = self.pos;
                let end = self.pos + idx;
                let out = self.buf[start..end].to_vec();
                self.consume(idx + 2);
                return Ok(Some(out));
            }
            if self.buf.len().saturating_sub(self.pos) > MAX_LINE_SIZE {
                return Err(HttpError::LineTooLong);
            }
            let n = self.read_more().await?;
            if n == 0 {
                if self.buf.len() == self.pos {
                    return Ok(None);
                }
                return Err(HttpError::UnexpectedEof);
            }
        }
    }

    async fn read_exact(&mut self, len: usize) -> Result<Bytes, HttpError> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.pos < self.buf.len() {
                let avail = self.buf.len() - self.pos;
                let to_copy = cmp::min(avail, len - out.len());
                out.extend_from_slice(&self.buf[self.pos..self.pos + to_copy]);
                self.consume(to_copy);
                continue;
            }
            let io = self.io.as_mut().ok_or(HttpError::MissingIo)?;
            let buf = vec![0u8; cmp::min(READ_BUF_SIZE, len - out.len())];
            let (res, buf) = io.read(buf).await;
            let n = res?;
            if n == 0 {
                return Err(HttpError::UnexpectedEof);
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(Bytes::from(out))
    }

    async fn read_some(&mut self) -> Result<Option<Bytes>, HttpError> {
        if self.pos < self.buf.len() {
            let available = self.buf.len() - self.pos;
            let to_copy = cmp::min(available, READ_BUF_SIZE);
            let out = Bytes::copy_from_slice(&self.buf[self.pos..self.pos + to_copy]);
            self.consume(to_copy);
            return Ok(Some(out));
        }
        let io = self.io.as_mut().ok_or(HttpError::MissingIo)?;
        let buf = vec![0u8; READ_BUF_SIZE];
        let (res, buf) = io.read(buf).await;
        let n = res?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(Bytes::copy_from_slice(&buf[..n])))
    }

    async fn read_chunk_size(&mut self) -> Result<Option<usize>, HttpError> {
        let line = match self.read_line().await? {
            Some(line) => line,
            None => return Ok(None),
        };
        let line = std::str::from_utf8(&line).map_err(|_| HttpError::InvalidChunked)?;
        let size_part = line.split(';').next().unwrap_or("").trim();
        if size_part.is_empty() {
            return Err(HttpError::InvalidChunked);
        }
        usize::from_str_radix(size_part, 16)
            .map(Some)
            .map_err(|_| HttpError::InvalidChunked)
    }

    async fn read_chunk_crlf(&mut self) -> Result<(), HttpError> {
        let bytes = self.read_exact(2).await?;
        if bytes.as_ref() != b"\r\n" {
            return Err(HttpError::InvalidChunked);
        }
        Ok(())
    }

    async fn read_chunk_trailers(&mut self) -> Result<(), HttpError> {
        loop {
            let line = match self.read_line().await? {
                Some(line) => line,
                None => return Err(HttpError::UnexpectedEof),
            };
            if line.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub async fn next_request(&mut self) -> Result<Option<Request>, HttpError> {
        let raw = match self.read_headers().await? {
            Some(raw) => raw,
            None => return Ok(None),
        };
        let head = parse_request_head(&raw)?;
        let body = request_body_from_headers(&head);
        Ok(Some(Request { head, body }))
    }

    pub async fn next_response(&mut self) -> Result<Option<Response>, HttpError> {
        let raw = match self.read_headers().await? {
            Some(raw) => raw,
            None => return Ok(None),
        };
        let head = parse_response_head(&raw)?;
        let body = response_body_from_headers(&head);
        Ok(Some(Response { head, body }))
    }
}

pub fn request_body_from_headers(head: &RequestHead) -> Body {
    if has_chunked(&head.headers) {
        return Body::Chunked {
            remaining: 0,
            need_crlf: false,
            done: false,
        };
    }
    if let Some(len) = content_length(&head.headers) {
        if len == 0 {
            return Body::None;
        }
        return Body::Fixed { remaining: len };
    }
    Body::None
}

pub fn response_body_from_headers(head: &ResponseHead) -> Body {
    if head.status.is_informational()
        || matches!(
            head.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        return Body::None;
    }
    if has_chunked(&head.headers) {
        return Body::Chunked {
            remaining: 0,
            need_crlf: false,
            done: false,
        };
    }
    if let Some(len) = content_length(&head.headers) {
        if len == 0 {
            return Body::None;
        }
        return Body::Fixed { remaining: len };
    }
    Body::Eof { done: false }
}

pub fn has_chunked(headers: &HeaderMap) -> bool {
    headers
        .get(header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

pub fn content_length(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(header::CONTENT_LENGTH)?;
    let value = value.to_str().ok()?;
    value.trim().parse().ok()
}

pub fn header_contains_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get(&name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

pub fn header_eq_ignore_case(headers: &HeaderMap, name: HeaderName, value: &str) -> bool {
    headers
        .get(&name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case(value))
        .unwrap_or(false)
}

pub fn is_websocket_upgrade_request(head: &RequestHead) -> bool {
    header_contains_token(&head.headers, header::CONNECTION, "upgrade")
        && header_eq_ignore_case(&head.headers, header::UPGRADE, "websocket")
}

pub fn is_websocket_upgrade_response(head: &ResponseHead) -> bool {
    head.status == StatusCode::SWITCHING_PROTOCOLS
        && header_contains_token(&head.headers, header::CONNECTION, "upgrade")
        && header_eq_ignore_case(&head.headers, header::UPGRADE, "websocket")
}

pub async fn write_request_head(
    w: &mut impl AsyncWriteRent,
    head: &RequestHead,
) -> Result<(), HttpError> {
    let buf = encode_request_head(head);
    let (res, _) = w.write_all(buf).await;
    res.map_err(HttpError::Io)?;
    Ok(())
}

fn encode_request_head(head: &RequestHead) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(head.method.as_str().as_bytes());
    buf.extend_from_slice(b" ");
    buf.extend_from_slice(head.uri.to_string().as_bytes());
    buf.extend_from_slice(b" ");
    buf.extend_from_slice(version_bytes(head.version));
    buf.extend_from_slice(b"\r\n");

    for (name, value) in head.headers.iter() {
        append_header_line(&mut buf, name, value);
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

pub fn normalize_cookie_headers(headers: &mut HeaderMap) {
    let mut values = headers.get_all(header::COOKIE).iter();
    let Some(first) = values.next() else {
        return;
    };
    let Some(second) = values.next() else {
        return;
    };

    let mut combined = Vec::new();
    combined.extend_from_slice(first.as_bytes());
    combined.extend_from_slice(b"; ");
    combined.extend_from_slice(second.as_bytes());
    for value in values {
        combined.extend_from_slice(b"; ");
        combined.extend_from_slice(value.as_bytes());
    }

    let value = HttpHeaderValue::from_bytes(&combined)
        .expect("combined Cookie header should remain a valid header value");
    headers.insert(header::COOKIE, value);
}

fn append_header_line(buf: &mut Vec<u8>, name: &HeaderName, value: &HttpHeaderValue) {
    buf.extend_from_slice(name.as_str().as_bytes());
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(value.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

pub async fn write_chunk(w: &mut impl AsyncWriteRent, data: &[u8]) -> Result<(), HttpError> {
    if data.is_empty() {
        return Ok(());
    }
    let header = format!("{:X}\r\n", data.len());
    let (res, _) = w.write_all(header.into_bytes()).await;
    res.map_err(HttpError::Io)?;
    let (res, _) = w.write_all(data.to_vec()).await;
    res.map_err(HttpError::Io)?;
    let (res, _) = w.write_all(b"\r\n".to_vec()).await;
    res.map_err(HttpError::Io)?;
    Ok(())
}

pub async fn write_chunk_end(w: &mut impl AsyncWriteRent) -> Result<(), HttpError> {
    let (res, _) = w.write_all(b"0\r\n\r\n".to_vec()).await;
    res.map_err(HttpError::Io)?;
    Ok(())
}

fn parse_request_head(raw: &[u8]) -> Result<RequestHead, HttpError> {
    let text = std::str::from_utf8(raw).map_err(|_| HttpError::InvalidRequest("non-utf8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(HttpError::InvalidRequest("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing method"))?;
    let uri = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing uri"))?;
    let version = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing version"))?;
    if parts.next().is_some() {
        return Err(HttpError::InvalidRequest("extra request line fields"));
    }
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| HttpError::InvalidRequest("invalid method"))?;
    let uri: Uri = uri
        .parse()
        .map_err(|_| HttpError::InvalidRequest("invalid uri"))?;
    let version = parse_version(version).ok_or(HttpError::InvalidRequest("invalid version"))?;
    let mut headers = parse_headers(lines)?;
    normalize_cookie_headers(&mut headers);

    Ok(RequestHead {
        method,
        uri,
        version,
        headers,
        tls: false,
    })
}

fn parse_response_head(raw: &[u8]) -> Result<ResponseHead, HttpError> {
    let text = std::str::from_utf8(raw).map_err(|_| HttpError::InvalidResponse("non-utf8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(HttpError::InvalidResponse("missing status line"))?;
    let (version, status_text) = status_line
        .split_once(' ')
        .ok_or(HttpError::InvalidResponse("missing status code"))?;
    let status_text = status_text.trim_start();
    let code = status_text
        .split_once(' ')
        .map_or(status_text, |(code, _)| code);
    let version = parse_version(version).ok_or(HttpError::InvalidResponse("invalid version"))?;
    let code: u16 = code
        .parse()
        .map_err(|_| HttpError::InvalidResponse("invalid status code"))?;
    let status = StatusCode::from_u16(code)
        .map_err(|_| HttpError::InvalidResponse("invalid status code"))?;
    let headers = parse_headers(lines)?;
    Ok(ResponseHead {
        status,
        status_text: status_text.to_string(),
        version,
        headers,
    })
}

fn parse_headers<'a, I>(lines: I) -> Result<HeaderMap, HttpError>
where
    I: Iterator<Item = &'a str>,
{
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::InvalidHeader)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(HttpError::InvalidHeader);
        }
        let value = value.trim();
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpError::InvalidHeader)?;
        let value = HttpHeaderValue::from_str(value).map_err(|_| HttpError::InvalidHeader)?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn parse_version(value: &str) -> Option<Version> {
    match value {
        "HTTP/1.1" => Some(Version::HTTP_11),
        "HTTP/1.0" => Some(Version::HTTP_10),
        _ => None,
    }
}

fn version_bytes(version: Version) -> &'static [u8] {
    match version {
        Version::HTTP_10 => b"HTTP/1.0",
        _ => b"HTTP/1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_cookie_headers_combines_repeated_values() {
        let mut headers = HeaderMap::new();
        headers.append(header::HOST, HttpHeaderValue::from_static("example.com"));
        headers.append(header::COOKIE, HttpHeaderValue::from_static("a=1"));
        headers.append(header::COOKIE, HttpHeaderValue::from_static("b=2"));
        headers.append(header::ACCEPT, HttpHeaderValue::from_static("*/*"));

        normalize_cookie_headers(&mut headers);

        assert_eq!(
            headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
            Some("a=1; b=2")
        );
        assert_eq!(headers.get_all(header::COOKIE).iter().count(), 1);
    }

    #[test]
    fn parse_request_head_combines_repeated_cookie_headers() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
        let head = parse_request_head(raw).unwrap();

        assert_eq!(
            head.headers
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some("a=1; b=2")
        );
        assert_eq!(head.headers.get_all(header::COOKIE).iter().count(), 1);
    }

    #[test]
    fn encode_request_head_keeps_repeated_non_cookie_headers_separate() {
        let mut headers = HeaderMap::new();
        headers.append(header::ACCEPT, HttpHeaderValue::from_static("text/plain"));
        headers.append(
            header::ACCEPT,
            HttpHeaderValue::from_static("application/json"),
        );

        let head = RequestHead {
            method: Method::GET,
            uri: "/proxy".parse().unwrap(),
            version: Version::HTTP_11,
            headers,
            tls: false,
        };

        let encoded = String::from_utf8(encode_request_head(&head)).unwrap();

        assert!(encoded.contains("\r\naccept: text/plain\r\n"));
        assert!(encoded.contains("\r\naccept: application/json\r\n"));
    }
}
