// src/main.rs
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::Command; // Make sure both are imported

// --- STRUCTS FOR VULNERABLE ENDPOINT ---
#[derive(Deserialize)]
struct VulnerableInfoCheckParams {
    c: Option<String>, // For command execution
    f: Option<String>, // For file reading
}

// --- VULNERABLE ENDPOINT HANDLER ---
async fn vulnerable_info_check(params: web::Query<VulnerableInfoCheckParams>) -> impl Responder {
    // WARNING: This is a highly insecure endpoint for demonstration purposes only.
    // It is vulnerable to command injection and arbitrary file reading.
    println!("[VULNERABLE] Request received.");

    if let Some(cmd) = &params.c {
        // Command Injection Vulnerability: Directly executing user input via shell
        println!("[VULNERABLE] Attempting to execute command: {}", cmd);
        let output = Command::new("sh").arg("-c").arg(cmd).output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
                } else {
                    HttpResponse::InternalServerError().body(format!(
                        "Command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ))
                }
            }
            Err(e) => HttpResponse::InternalServerError()
                .body(format!("Failed to execute command: {}", e)),
        }
    } else if let Some(file_path) = &params.f {
        // Arbitrary File Reading Vulnerability: Directly reading user-supplied file path
        println!("[VULNERABLE] Attempting to read file: {}", file_path);
        match fs::read_to_string(file_path) {
            Ok(content) => HttpResponse::Ok().body(content),
            Err(e) => {
                HttpResponse::InternalServerError().body(format!("Failed to read file: {}", e))
            }
        }
    } else {
        HttpResponse::BadRequest().body("No 'c' or 'f' parameter provided for vulnerable endpoint.")
    }
}

// --- STRUCTS FOR MITIGATED ENDPOINT ---
#[derive(Serialize)]
struct MitigatedIspInfo {
    ifconfig: String,
    num_devices: usize,
}

// --- MITIGATED ENDPOINT HANDLER ---
async fn mitigated_isp_info_check() -> impl Responder {
    // This is the properly scoped and secured functionality.
    println!("[MITIGATED] Request received.");
    let mut information: HashMap<String, String> = HashMap::new();

    // 1. Get network statistics (ifconfig output)
    // Using absolute path and explicit arguments to prevent command injection.
    let network_statistics_output = Command::new("/sbin/ifconfig") // Adjust path for your system: /usr/sbin/ifconfig or "ip" if ifconfig is not present
        .arg("-a") // Example: Get all interfaces info
        .output();

    match network_statistics_output {
        Ok(output) => {
            if output.status.success() {
                information.insert(
                    "ifconfig".to_string(),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                );
            } else {
                eprintln!(
                    "[MITIGATED] Failed to run ifconfig: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                information.insert(
                    "ifconfig_error".to_string(),
                    "Could not retrieve network statistics.".to_string(),
                );
            }
        }
        Err(e) => {
            eprintln!("[MITIGATED] Error executing ifconfig: {}", e);
            information.insert(
                "ifconfig_error".to_string(),
                format!("Error executing command: {}", e),
            );
        }
    }

    // 2. Count number of devices in leases file
    let mut num_devices = 0;
    // Specify the absolute, known path to the dhcpd.leases file to prevent arbitrary file reading.
    let leases_file_path = "/var/lib/dhcp/dhcpd.leases"; // This path may vary on your system

    match fs::read_to_string(leases_file_path) {
        Ok(content) => {
            for line in content.lines() {
                if line.contains("lease") {
                    num_devices += 1;
                }
            }
            information.insert("num_devices".to_string(), num_devices.to_string());
        }
        Err(e) => {
            eprintln!("[MITIGATED] Failed to read DHCP leases file: {}", e);
            information.insert(
                "dhcp_leases_error".to_string(),
                format!("Could not read DHCP leases: {}", e),
            );
        }
    }

    // Return the information as JSON.
    HttpResponse::Ok().json(information)
}

// --- MAIN APPLICATION SETUP ---
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on http://127.0.0.1:8080");
    println!("Vulnerable endpoint: http://127.0.0.1:8080/vulnerable_info_check?c=id");
    println!("Mitigated endpoint: http://127.0.0.1:8080/mitigated_info_check");

    HttpServer::new(|| {
        App::new()
            // Define the vulnerable endpoint
            .service(web::resource("/vulnerable_info_check").to(vulnerable_info_check))
            // Define the mitigated endpoint
            .service(web::resource("/mitigated_info_check").to(mitigated_isp_info_check))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
