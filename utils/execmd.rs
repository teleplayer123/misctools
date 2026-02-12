use std::process::{Command, Stdio};
use std::io::{self, Read, Write};

fn run_powershell_command(command: &str) -> Result<String, io::Error> {
    let mut powershell = Command::new("powershell")
        .arg("-Command")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdout = powershell.stdout.take().unwrap();
    let mut stderr = powershell.stderr.take().unwrap();

    let mut stdout_string = String::new();
    let mut stderr_string = String::new();

    stdout.read_to_string(&mut stdout_string)?;
    stderr.read_to_string(&mut stderr_string)?;

    let status = powershell.wait()?;

    if status.success() {
        Ok(stdout_string)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("PowerShell command failed: {}\nError: {}", status, stderr_string),
        ))
    }
}

fn main() {
    // Process info command
    let command = "Get-Process | Where-Object {$_.CPU -gt 1} | Sort-Object CPU -Descending | Select-Object -First 5 | Format-List Name, CPU, WorkingSet";
    match run_powershell_command(command) {
        Ok(output) => {
            println!("PowerShell Output:\n{}", output);
        }
        Err(err) => {
            eprintln!("Error running PowerShell command: {}", err);
        }
    }

    // Date command
    let command2 = "Get-Date";
    match run_powershell_command(command2) {
        Ok(output) => {
            println!("PowerShell Output:\n{}", output);
        }
        Err(err) => {
            eprintln!("Error running PowerShell command: {}", err);
        }
    }
}
