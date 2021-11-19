use native_tls::{TlsConnector, TlsStream};
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::env;
use std::io::BufReader;
use std::str::from_utf8;
use regex::Regex;
use select::document::Document;
use select::predicate::{Class, Name, Predicate};
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
    let mut close_connection = false;
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
        if line.starts_with("Connection: close") {
            close_connection = true;
        }
        more_header = !line.eq("\r\n");
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();

    if close_connection {
        *stream = setup_connection();
    }

    from_utf8(&body).unwrap().to_owned()
}

fn get_url(url: &str, stream: &mut TlsStream<TcpStream>, cookies: &mut HashMap<String, String>, frontier: &mut Queue<String>) -> String {
    let mut cookie_header = String::new();
    cookie_header.push_str("\r\nCookie: ");
    for (name, value) in cookies.clone() {
        cookie_header.push_str(&name);
        cookie_header.push_str("=");
        cookie_header.push_str(&value);
        cookie_header.push_str("; ");
    }
    let get_message = format!("GET {} HTTP/1.1\r\nHost: fakebook.3700.network:443{}\r\n\r\n", url, cookie_header);
    stream.write_all(get_message.as_bytes()).unwrap();

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
    let post_message = format!("POST /accounts/login/?next=/fakebook/ HTTP/1.1\r\nHost: fakebook.3700.network:443\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}{}\r\n\r\n{}", content_length, cookie_header, content);
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

fn get_secret_flag(html: &str) -> bool {
    for secret_flag in Document::from(html).find(Class("secret_flag")).filter_map(|n| Some(n.text())) {
        let secret_flag_re = Regex::new(r"FLAG: (?P<flag>*{64})").unwrap();
        let caps = secret_flag_re.captures(&secret_flag).unwrap();
        println!("{}", &caps["flag"]);
        return true;
    }
    return false;
}

fn parse_html_page(html: String, frontier: &mut Queue<String>)  -> bool {
    for url in get_links_from_html(&html) {
        frontier.add(url).unwrap();
    }
    get_secret_flag(&html)
}

fn setup_connection() -> TlsStream<TcpStream> {
    let hostname = "fakebook.3700.network";
    let port = 443;

    // Setup connection
    let connector = TlsConnector::new().unwrap();
    let stream = TcpStream::connect((hostname, port)).unwrap();
    connector.connect(hostname, stream).unwrap()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let username = &args[1];
    let password = &args[2];
    
    let mut stream = setup_connection();
    let mut cookies = HashMap::<String, String>::new();
    let mut frontier = queue![];
    let mut num_secret_flags_found = 0;

    let login_page = get_url("/accounts/login/?next=/fakebook/", &mut stream, &mut cookies, &mut frontier);

    let csrf_token = parse_csrf_token(&login_page);
    
    let _login_response = login(username, password, &csrf_token, &mut stream, &mut cookies, &mut frontier);

    let mut visited_pages = HashSet::<String>::new();
    frontier.add("/fakebook/".to_string()).unwrap();
    frontier.remove().unwrap();

    while frontier.size() > 0 && num_secret_flags_found < 5 {
        let url = frontier.remove().unwrap();
        if !visited_pages.contains(&url) && url.starts_with("/") && !url.starts_with("/accounts/logout/") {
            let page = get_url(&url, &mut stream, &mut cookies, &mut frontier);
            visited_pages.insert(url);
            if parse_html_page(page, &mut frontier) {
                num_secret_flags_found += 1;
            }
        }
    }
}