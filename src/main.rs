extern crate imap;
extern crate mailparse;
extern crate native_tls;
extern crate notify_rust;
extern crate rayon;
extern crate systray;
extern crate toml;
extern crate xdg;
extern crate openssl;

use native_tls::{TlsConnector, TlsConnectorBuilder, TlsStream};
use native_tls::backend::openssl::TlsConnectorBuilderExt;
use openssl::ssl;
use openssl::x509::X509;
use imap::client::Client;
use rayon::prelude::*;

use std::process::Command;
use std::io::prelude::*;
use std::net::TcpStream;
use std::time::Duration;
use std::sync::mpsc;
use std::fs::File;
use std::thread;

#[derive(Clone)]
struct Account {
    name: String,
    server: (String, u16),
    sni_domain: String,
    server_cert_data: Option<Vec<u8>>,
    username: String,
    password: String, // TODO: this should not stay in memory
}

struct Connection<T: Read + Write> {
    account: Account,
    socket: Client<T>,
}

impl Account {
    pub fn connect(&self) -> Result<Connection<TlsStream<TcpStream>>, imap::error::Error> {
        let tls = match self.server_cert_data {
            Some(ref pem_data) => {
                let cert = X509::from_pem(pem_data).unwrap();
                let mut ssl_cb = ssl::SslConnectorBuilder::new(ssl::SslMethod::tls()).unwrap();
                // the certificate needs to be injected directly into the store, there's no API for loading in-memory certs
                ssl_cb.builder_mut().cert_store_mut().add_cert(cert).expect("Failed to add cert");
                TlsConnectorBuilder::from_openssl(ssl_cb)
            }
            None => TlsConnector::builder()?
        }.build()?;
        let mut conn = Client::connect((&*self.server.0, self.server.1))?;
        if !conn.capability()?.iter().any(|c| c == "STARTTLS") {
            panic!("STARTTLS not in capabilities");
        }
        let mut conn = conn.secure(&self.sni_domain, tls).unwrap();
        conn.login(&self.username, &self.password)?;
        if !conn.capability()?.iter().any(|c| c == "IDLE") {
            panic!("IDLE not in capabilities");
        }

        try!(conn.select("INBOX"));
        Ok(Connection {
            account: self.clone(),
            socket: conn,
        })
    }
}

impl<T: Read + Write + imap::client::SetReadTimeout> Connection<T> {
    pub fn handle(mut self, account: usize, mut tx: mpsc::Sender<(usize, usize)>) {
        loop {
            if let Err(_) = self.check(account, &mut tx) {
                // the connection has failed for some reason
                // try to log out (we probably can't)
                self.socket.logout().is_err();
                break;
            }
        }

        // try to reconnect
        let mut wait = 1;
        for _ in 0..5 {
            println!(
                "connection to {} lost; trying to reconnect...",
                self.account.name
            );
            match self.account.connect() {
                Ok(c) => {
                    println!("{} connection reestablished", self.account.name);
                    return c.handle(account, tx);
                }
                Err(imap::error::Error::Io(_)) => {
                    thread::sleep(Duration::from_secs(wait));
                }
                Err(_) => break,
            }

            wait *= 2;
        }
    }

    fn check(
        &mut self,
        account: usize,
        tx: &mut mpsc::Sender<(usize, usize)>,
    ) -> Result<(), imap::error::Error> {
        // Keep track of all the e-mails we have already notified about
        let mut last_notified = 0;

        loop {
            // check current state of inbox
            let mut unseen = self.socket
                .run_command_and_read_response("UID SEARCH UNSEEN 1:*")?;

            // remove last line of response (OK Completed)
            unseen.pop();

            let mut num_unseen = 0;
            let mut uids = Vec::new();
            let unseen = unseen.join(" ");
            let unseen = unseen.split_whitespace().skip(2);
            for uid in unseen.take_while(|&e| e != "" && e != "Completed") {
                if let Ok(uid) = usize::from_str_radix(uid, 10) {
                    if uid > last_notified {
                        last_notified = uid;
                        uids.push(format!("{}", uid));
                    }
                    num_unseen += 1;
                }
            }

            let mut subjects = Vec::new();
            if !uids.is_empty() {
                let mut finish = |message: &[u8]| -> bool {
                    match mailparse::parse_headers(message) {
                        Ok((headers, _)) => {
                            use mailparse::MailHeaderMap;
                            match headers.get_first_value("Subject") {
                                Ok(Some(subject)) => {
                                    subjects.push(subject);
                                    return true;
                                }
                                Ok(None) => {
                                    subjects.push(String::from("<no subject>"));
                                    return true;
                                }
                                Err(e) => {
                                    println!("failed to get message subject: {:?}", e);
                                }
                            }
                        }
                        Err(e) => println!("failed to parse headers of message: {:?}", e),
                    }
                    false
                };

                let lines = self.socket.uid_fetch(&uids.join(","), "RFC822.HEADER")?;
                let mut message = Vec::new();
                for line in &lines {
                    if line.starts_with("* ") {
                        if !message.is_empty() {
                            finish(&message[..]);
                            message.clear();
                        }
                        continue;
                    }
                    message.extend(line.as_bytes());
                }
                finish(&message[..]);
            }

            if !subjects.is_empty() {
                use notify_rust::{Notification, NotificationHint};
                let title = format!(
                    "@{} has new mail ({} unseen)",
                    self.account.name,
                    num_unseen
                );
                let notification = format!("> {}", subjects.join("\n> "));
                println!("! {}", title);
                println!("{}", notification);
                Notification::new()
                    .summary(&title)
                    .body(&notification)
                    .icon("notification-message-email")
                    .hint(NotificationHint::Category("email".to_owned()))
                    .timeout(-1)
                    .show()
                    .expect("failed to launch notify-send");
            }

            tx.send((account, num_unseen)).unwrap();

            // IDLE until we see changes
            self.socket.idle()?.wait_keepalive()?;
        }
    }
}

fn main() {
    // Load the user's config
    let xdg = match xdg::BaseDirectories::new() {
        Ok(xdg) => xdg,
        Err(e) => {
            println!("Could not find configuration file buzz.toml: {}", e);
            return;
        }
    };
    let config = match xdg.find_config_file("buzz.toml") {
        Some(config) => config,
        None => {
            println!("Could not find configuration file buzz.toml");
            return;
        }
    };
    let config = {
        let mut f = match File::open(config) {
            Ok(f) => f,
            Err(e) => {
                println!("Could not open configuration file buzz.toml: {}", e);
                return;
            }
        };
        let mut s = String::new();
        if let Err(e) = f.read_to_string(&mut s) {
            println!("Could not read configuration file buzz.toml: {}", e);
            return;
        }
        match s.parse::<toml::Value>() {
            Ok(t) => t,
            Err(e) => {
                println!("Could not parse configuration file buzz.toml: {}", e);
                return;
            }
        }
    };

    // Figure out what accounts we have to deal with
    let accounts: Vec<_> = match config.as_table() {
        Some(t) => t.iter()
            .filter_map(|(name, v)| match v.as_table() {
                None => {
                    println!("Configuration for account {} is broken: not a table", name);
                    None
                }
                Some(t) => {
                    let pwcmd = match t.get("pwcmd").and_then(|p| p.as_str()) {
                        None => return None,
                        Some(pwcmd) => pwcmd,
                    };
                    let password = Command::new("sh")
                        .arg("-c")
                        .arg(pwcmd)
                        .output()
                        .map(|output| {
                            if !output.status.success() {
                                panic!("Command failed: {}", pwcmd)
                            }
                            let s = String::from_utf8(output.stdout).expect("Password is not utf-8");
                            s.trim_right_matches('\n').to_owned()
                        })
                        .map_err(|e| panic!("Failed to launch password command for {}: {}", name, e))
                        .unwrap();

                    let pem_data = t.get("server_cert")
                        .map(|v| v.as_str().expect("Server cert must be a string"))
                        .map(|path| {
                            let mut f = File::open(path).expect(&format!("Could not open {}", path));
                            let mut pem = Vec::new();
                            f.read_to_end(&mut pem).expect(&format!("Failed to read {}", path));
                            pem
                        });
                    if let &Some(ref p) = &pem_data {
                        X509::from_pem(p).expect(&format!("Cert in {} is not PEM", name)); // X509 is not Send, and therefore can't be used later on while connecting
                    }

                    let server_name = t["server"].as_str().unwrap();
                    Some(Account {
                        name: name.as_str().to_owned(),
                        server: (
                            server_name.to_owned(),
                            t["port"].as_integer().unwrap() as u16,
                        ),
                        sni_domain: match t.get("sni_domain") {
                            Some(data) => data.as_str().unwrap().to_owned(),
                            None => server_name.to_owned(),
                        },
                        server_cert_data: pem_data,
                        username: t["username"].as_str().unwrap().to_owned(),
                        password: password,
                    })
                }
            })
            .collect(),
        None => {
            println!("Could not parse configuration file buzz.toml: not a table");
            return;
        }
    };

    if accounts.is_empty() {
        println!("No accounts in config; exiting...");
        return;
    }

    // Create a new application
    let mut app = match systray::Application::new() {
        Ok(app) => app,
        Err(e) => {
            println!("Could not create gtk application: {}", e);
            return;
        }
    };
    if let Err(e) = app.set_icon_from_file(&"/usr/share/icons/Faenza/stock/24/stock_disconnect.png"
        .to_string())
    {
        println!("Could not set application icon: {}", e);
    }
    if let Err(e) = app.add_menu_item(&"Quit".to_string(), |window| {
        window.quit();
    }) {
        println!("Could not add application Quit menu option: {}", e);
    }

    // TODO: w.set_tooltip(&"Whatever".to_string());
    // TODO: app.wait_for_message();

    let accounts: Vec<_> = accounts
        .par_iter()
        .filter_map(|account| {
            let mut wait = 1;
            for _ in 0..5 {
                match account.connect() {
                    Ok(c) => return Some(c),
                    Err(imap::error::Error::Io(e)) => {
                        println!(
                            "Failed to connect account {}: {}; retrying in {}s",
                            account.name,
                            e,
                            wait
                        );
                        thread::sleep(Duration::from_secs(wait));
                    }
                    Err(e) => {
                        println!("{} host produced bad IMAP tunnel: {}", account.name, e);
                        break;
                    }
                }

                wait *= 2;
            }

            None
        })
        .collect();

    if accounts.is_empty() {
        println!("No accounts in config worked; exiting...");
        return;
    }

    // We have now connected
    app.set_icon_from_file(&"/usr/share/icons/Faenza/stock/24/stock_connect.png"
        .to_string())
        .ok();

    let (tx, rx) = mpsc::channel();
    let mut unseen: Vec<_> = accounts.iter().map(|_| 0).collect();
    for (i, conn) in accounts.into_iter().enumerate() {
        let tx = tx.clone();
        thread::spawn(move || {
            conn.handle(i, tx);
        });
    }

    for (i, num_unseen) in rx {
        unseen[i] = num_unseen;
        if unseen.iter().sum::<usize>() == 0 {
            app.set_icon_from_file(&"/usr/share/icons/oxygen/base/32x32/status/mail-unread.png"
                .to_string())
                .unwrap();
        } else {
            app.set_icon_from_file(
                &"/usr/share/icons/oxygen/base/32x32/status/mail-unread-new.png".to_string(),
            ).unwrap();
        }
    }
}
