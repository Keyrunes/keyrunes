use std::process::Command;

#[test]
fn test_cli_help() {
    // Act
    let output = Command::new("cargo")
        .args(["run", "--bin", "cli", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    // Assert
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: cli"));
}

#[test]
fn test_cli_create_user_help() {
    // Act
    let output = Command::new("cargo")
        .args(["run", "--bin", "cli", "--", "register", "--help"])
        .output()
        .expect("Failed to execute command");

    // Assert
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: cli register"));
}
