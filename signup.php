<?php
// Database configuration
$servername = "127.0.0.1"; // Or "localhost"
$username = "root";        // Default MySQL username for XAMPP
$password = "";            // Default MySQL password is empty in XAMPP
$dbname = "pgs_user";      // Your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm password']);

    // Validate form data
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        echo "All fields are required!";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format!";
        exit;
    }

    if ($password !== $confirm_password) {
        echo "Passwords do not match!";
        exit;
    }

    // Hash the password for secure storage
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Check if the email already exists
    $check_sql = "SELECT id FROM users WHERE email = ?";
    if ($check_stmt = $conn->prepare($check_sql)) {
        $check_stmt->bind_param("s", $email);
        $check_stmt->execute();
        $check_stmt->store_result();
        if ($check_stmt->num_rows > 0) {
            echo "This email is already registered!";
            $check_stmt->close();
            exit;
        }
        $check_stmt->close();
    } else {
        echo "Error: " . $conn->error;
        exit;
    }

    // Insert user data into the database
    $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("sss", $username, $email, $hashed_password);
        if ($stmt->execute()) {
            // Redirect to login page or show success message
            echo "Registration successful! <a href='login.html'>Login here</a>.";
        } else {
            echo "Error inserting data: " . $stmt->error;
        }
        $stmt->close();
    } else {
        echo "Error: " . $conn->error;
    }
}

// Close connection
$conn->close();
?>
