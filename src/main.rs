use native_tls::{TlsConnector, TlsStream};
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::env;
use std::io::BufReader;
use std::str::from_utf8;
use regex::Regex;
use select::document::Document;
use select::predicate::{Name, Predicate};
use std::collections::{HashMap, HashSet};

extern crate queues;
use queues::*;

fn parse_csrf_token(html: &str) -> String {
    Document::from(html)
        .find(Name("input"))
        .filter(|n| n.attr("name").unwrap().eq("csrfmiddlewaretoken"))
        .filter_map(|n| n.attr("value"))
        .next().unwrap().to_string()
}

fn read_http_response(mut stream: &mut TlsStream<TcpStream>, cookies: &mut HashMap<String, String>, frontier: &mut Queue<String>) -> String {
    let mut reader = BufReader::new(&mut stream);
    let mut content_length = 0usize;
    let mut more_header = true;
    let content_length_re = Regex::new(r"Content-Length: (?P<length>\d*)").unwrap();
    let set_cookie_re = Regex::new(r"Set-Cookie: (?P<name>[^=]*)=(?P<value>[^;]*);").unwrap();
    let found_url_re = Regex::new(r"Location: (?P<url>[^ ]*)").unwrap();

    while more_header {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.starts_with("Content-Length: ") {
            let caps = content_length_re.captures(&line).unwrap();
            content_length = caps["length"].parse::<usize>().unwrap();
        }
        if line.starts_with("Set-Cookie: ") {
            let caps = set_cookie_re.captures(&line).unwrap();
            cookies.insert(caps["name"].to_string(), caps["value"].to_string());
        }
        if line.starts_with("Location: ") {
            let caps = found_url_re.captures(&line).unwrap();
            frontier.add(caps["url"].to_string()).unwrap();
        }
        more_header = !line.eq("\r\n");
        print!("{}", line);
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();

    from_utf8(&body).unwrap().to_owned()
}

fn get_url(url: &str, stream: &mut TlsStream<TcpStream>, cookies: &mut HashMap<String, String>, frontier: &mut Queue<String>) -> String {
    stream.write_all(format!("GET {}/ HTTP/1.1\r\nHost: fakebook.3700.network\r\n\r\n", url).as_bytes()).unwrap();

    read_http_response(stream, cookies, frontier)
}

fn login(username: &str, password: &str, csrf_token: &str, stream: &mut TlsStream<TcpStream>, cookies: &mut HashMap<String, String>, frontier: &mut Queue<String>) -> String {
    let content = format!("username={}&password={}&csrfmiddlewaretoken={}", username, password, csrf_token);
    let mut cookie_header = String::new();
    cookie_header.push_str("\r\nCookie: ");
    for (name, value) in cookies.clone() {
        cookie_header.push_str(&name);
        cookie_header.push_str("=");
        cookie_header.push_str(&value);
    }
    let content_length = content.len();
    let post_message = format!("POST /accounts/login/?next=/fakebook/ HTTP/1.1\r\nHost: fakebook.3700.network\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}{}\r\n\r\n{}", content_length, cookie_header, content);
    stream.write_all(post_message.as_bytes()).unwrap();

    read_http_response(stream, cookies, frontier)
}

fn get_links_from_html(html: &str) -> HashSet<String> {
    Document::from(html)
        .find(Name("a").or(Name("link")))
        .filter_map(|n| n.attr("href"))
        .map(|s| s.to_string())
        .collect::<HashSet<String>>()
}

fn parse_html_page(html: String, frontier: &mut Queue<String>) {
    for url in get_links_from_html(&html) {
        frontier.add(url).unwrap();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let username = &args[1];
    let password = &args[2];
    println!("Username: {}", username);
    println!("Password: {}", password);
    let hostname = "fakebook.3700.network";
    let port = 443;

    // Setup connection
    let connector = TlsConnector::new().unwrap();
    let stream = TcpStream::connect((hostname, port)).unwrap();
    let mut stream = connector.connect(hostname, stream).unwrap();
    let mut cookies = HashMap::<String, String>::new();
    let mut frontier = queue![];

    let login_page = get_url("/accounts/login/?next=/fakebook/", &mut stream, &mut cookies, &mut frontier);

    // Parse login page for csrf middleware token
    let csrf_token = parse_csrf_token(&login_page);
    
    // Post login request
    let _login_response = login(username, password, &csrf_token, &mut stream, &mut cookies, &mut frontier);
    // println!("{}", login_response);

    let mut visited_pages = HashSet::<String>::new();
    frontier.add("/fakebook".to_string()).unwrap();

    while frontier.size() > 0 {
        let url = frontier.remove().unwrap();
        if !visited_pages.contains(&url) && url.starts_with("/") {
            println!("visiting {}", url);
            let page = get_url(&url, &mut stream, &mut cookies, &mut frontier);
            visited_pages.insert(url);
            parse_html_page(page, &mut frontier);
        }
    }
}

// use std::env;
// //use std::io::Read;
// use select::document::Document;
// use select::predicate::{Name, Predicate};
// use std::net::ToSocketAddrs;
// use std::net::TcpStream;

// extern crate rustls; // 0.17.0

// use io::Read;
// use io::Write;
// use std::io;

// fn get_links_from_html(html: &str) -> HashSet<String> {
//     Document::from(html)
//         .find(Name("a").or(Name("link")))
//         .filter_map(|n| n.attr("href"))
//         .filter_map(normalize_url)
//         .collect::<HashSet<String>>()
// }

// fn normalize_url(url: &str) -> Option<String> {
//     if url.starts_with('/') {
//         Some(format!("https://fakebook.3700.network{}", url))
//     } else if url.starts_with("https://fakebook.3700.network") {
//         Some(url.to_string())
//     }
//     else {
//         None
//     }
// }

// fn fetch_url(client: &reqwest::blocking::Client, url: &str) -> String {
//     let mut res = client.get(url).send().unwrap();
//     println!("Status for {}: {}", url, res.status());

//     let mut body  = String::new();
//     res.read_to_string(&mut body).unwrap();
//     body
// }

// fn parse_csrf_token(html: &str) -> String {
//     Document::from(html)
//         .find(Name("input"))
//         .filter(|n| n.attr("name").unwrap().eq("csrfmiddlewaretoken"))
//         .filter_map(|n| n.attr("value"))
//         .next().unwrap().to_string()
// }

// fn main() {
//     let args: Vec<String> = env::args().collect();
    
//     let username = &args[1];
//     let password = &args[2];

//     println!("Username: {}", username);
//     println!("Password: {}", password);

//     // let hostname = "fakebook.3700.network";
//     // let port = 443;

//     // let mut stream = TcpStream::connect((hostname, port).to_socket_addrs().unwrap().next().unwrap()).unwrap();

//     let mut socket = std::net::TcpStream::connect("www.google.com:443").unwrap();
//     let mut config = rustls::ClientConfig::new();
//     config
//         .root_store
//         .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
//     let arc = std::sync::Arc::new(config);
//     let dns_name = webpki::DNSNameRef::try_from_ascii_str("www.google.com").unwrap();
//     let mut client = rustls::ClientSession::new(&arc, dns_name);
//     let mut stream = rustls::Stream::new(&mut client, &mut socket); // Create stream
//                                                                     // Instead of writing to the client, you write to the stream
//     stream
//         .write(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
//         .unwrap();
//     let mut plaintext = Vec::new();
//     stream.read_to_end(&mut plaintext).unwrap();
//     io::stdout().write_all(&plaintext).unwrap();
// }

//     // let client = reqwest::blocking::Client::builder()
//     //     .cookie_store(true)
//     //     .build().unwrap();

//     // let login_url = "https://fakebook.3700.network/accounts/login/?next=/fakebook/";
//     // let body = fetch_url(&client, login_url);
//     // let csrf_token = parse_csrf_token(&body);
//     // println!("\n\ncsrf token: {}", csrf_token);
//     // let params = [("username", username), ("password", password), ("csrfmiddlewaretoken", &csrf_token)];
//     // let mut res = client.post(login_url).form(&params).send().unwrap();
//     // println!("Status for {}: {}", login_url, res.status());

//     // let origin_url = "https://fakebook.3700.network/fakebook/";
    
//     // let body = fetch_url(&client, origin_url);

//     // let mut visited = HashSet::new();
//     // visited.insert(origin_url.to_string());
//     // let found_urls = get_links_from_html(&body);
//     // let mut new_urls = found_urls
//     // 	.difference(&visited)
//     //     .map(|x| x.to_string())
//     //     .collect::<HashSet<String>>();

//     // while !new_urls.is_empty() {
//     //     let found_urls: HashSet<String> = new_urls.iter().map(|url| {
//     //         let body = fetch_url(&client, url);
//     //         let links = get_links_from_html(&body);
//     //         println!("Visited: {} found {} links", url, links.len());
//     //         links
//     //     }).fold(HashSet::new(), |mut acc, x| {
//     //             acc.extend(x);
//     //             acc
//     //     });
//     //     visited.extend(new_urls);
        
//     //     new_urls = found_urls
//     //     	.difference(&visited)
//     //         .map(|x| x.to_string())
//     //         .collect::<HashSet<String>>();
//     //     println!("New urls: {}", new_urls.len())
//     // }
//     // println!("URLs: {:#?}", visited);
// // }