use std::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::io::{Read, Write, Error};

fn handle_client(mut stream: TcpStream) -> Result<(), Error> {
    println!("Incoming connection from: {}", stream.peer_addr()?);
    let mut buf = [0; 512];
    loop {
        let bytes_read = stream.read(&mut buf)?;
        if bytes_read == 0 { return Ok(()) }
        stream.write(&buf[..bytes_read])?;
    }
}

fn main() {
    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();

    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {
        match stream {
            Err(e) => { eprintln!("failed: {}", e) }
            Ok(stream) => {handle_client(stream).unwrap()}
            }
    }
}