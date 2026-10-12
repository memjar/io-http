#![no_main]

//! Coverage-guided fuzz target for the response parsers. The oracle:
//! whatever a server sends, split however the transport splits it, the
//! HTTP/1.0 and HTTP/1.1 send coroutines and the streaming chunk decoder
//! answer or fail, never panic, never spin on EOF, and never return a
//! body larger than the limit they were given.

use arbitrary::Arbitrary;
use io_http::{
    coroutine::*,
    rfc1945::send::Http10Send,
    rfc9110::{request::HttpRequest, send::*},
    rfc9112::{
        chunk_stream::{Http11ChunksReadStream, Http11ChunksReadStreamYield},
        send::Http11Send,
    },
};
use libfuzzer_sys::fuzz_target;
use url::Url;

/// How many reads a coroutine may still ask for once EOF was reported.
const MAX_READS_AFTER_EOF: usize = 2;

#[derive(Arbitrary, Debug)]
struct Input {
    max_headers_len: u16,
    max_body_len: u16,
    reads: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    let max_headers_len = usize::from(input.max_headers_len);
    let max_body_len = usize::from(input.max_body_len);

    let url = Url::parse("http://example.com/").unwrap();
    let request = HttpRequest::get(url).header("Host", "example.com");

    let mut send = Http11Send::new(request.clone());
    send.max_headers_len = max_headers_len;
    send.max_body_len = max_body_len;
    check_send(send, &input.reads, max_body_len);

    let mut send = Http10Send::new(request);
    send.max_headers_len = max_headers_len;
    send.max_body_len = max_body_len;
    check_send(send, &input.reads, max_body_len);

    let mut chunks = Http11ChunksReadStream::default();
    chunks.max_chunk_len = max_body_len;
    check_chunk_stream(chunks, &input.reads, max_body_len);
});

fn check_send<C, E>(mut send: C, reads: &[Vec<u8>], max_body_len: usize)
where
    C: HttpCoroutine<Yield = HttpSendYield, Return = Result<HttpSendOutput, E>>,
{
    let mut reads = reads.iter().filter(|r| !r.is_empty());
    let mut reads_after_eof = 0;
    let mut arg: Option<&[u8]> = None;

    loop {
        match send.resume(arg.take()) {
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(_)) => {}
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => match reads.next() {
                Some(read) => arg = Some(read),
                None => {
                    reads_after_eof += 1;
                    assert!(reads_after_eof <= MAX_READS_AFTER_EOF, "spins on EOF");
                    arg = Some(b"");
                }
            },
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { response, .. }) => {
                assert!(response.body.len() <= max_body_len);
                return;
            }
            HttpCoroutineState::Complete(Ok(out)) => {
                assert!(out.response.body.len() <= max_body_len);
                return;
            }
            HttpCoroutineState::Complete(Err(_)) => return,
        }
    }
}

fn check_chunk_stream(mut chunks: Http11ChunksReadStream, reads: &[Vec<u8>], max_len: usize) {
    let mut reads = reads.iter().filter(|r| !r.is_empty());
    let mut reads_after_eof = 0;
    let mut arg: Option<&[u8]> = None;

    loop {
        match chunks.resume(arg.take()) {
            HttpCoroutineState::Yielded(Http11ChunksReadStreamYield::Frame { body }) => {
                assert!(body.len() <= max_len);
            }
            HttpCoroutineState::Yielded(Http11ChunksReadStreamYield::WantsRead) => {
                match reads.next() {
                    Some(read) => arg = Some(read),
                    None => {
                        reads_after_eof += 1;
                        assert!(reads_after_eof <= MAX_READS_AFTER_EOF, "spins on EOF");
                        arg = Some(b"");
                    }
                }
            }
            HttpCoroutineState::Complete(_) => return,
        }
    }
}
