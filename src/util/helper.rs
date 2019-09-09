use std::{
    future::Future,
    io::Result as IoResult,
};

use futures::FutureExt;

/// generic error handler running spawned future.
// ToDo: add log and error report.
pub fn spawn_handler<F>(f: F)
    where F: Future<Output=IoResult<()>> + Send + 'static {
    tokio::spawn(f.map(|e| {
        if let Err(e) = e {
            println!("{:?}", e.to_string())
        }
    }));
}