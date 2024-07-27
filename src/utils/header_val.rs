use axum::http::HeaderValue;

#[inline]
fn is_valid(b: u8) -> bool {
    b >= 32 && b != 127 || b == b'\t'
}

pub fn header_val_lossy(val: impl AsRef<[u8]>) -> HeaderValue {
    let mut bytes = Vec::with_capacity(val.as_ref().len());
    for &b in val.as_ref() {
        if is_valid(b) {
            bytes.push(b);
        } else {
            bytes.push(b'?');
        }
    }

    unsafe {
        // SAFETY: we removed all invalid bytes
        HeaderValue::from_maybe_shared_unchecked(bytes)
    }
}
