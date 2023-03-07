<?php
// Include database connection
require_once('../register/db.php');

// Start the session
session_start();



// Get the user id
$id = $_SESSION['id'];

// Define variables and initialize with empty values
$username = $email = $password = $new_password = $confirm_password = "";
$username_err = $email_err = $password_err = $new_password_err = $confirm_password_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Validate name
    if(empty(trim($_POST["name"]))){
        $username_err = "Please enter a username.";
    } else{
        $username = trim($_POST["name"]);
    }

    // Validate email
    if(empty(trim($_POST["email"]))){
        $email_err = "Please enter an email.";
    } else{
        $email = trim($_POST["email"]);
    }

    // Validate password
    if(!empty(trim($_POST["password"]))){
        $password = trim($_POST["password"]);
    }

    // Validate new password
    if(!empty(trim($_POST["new_password"]))){
        $new_password = trim($_POST["new_password"]);
    }

    // Validate confirm password
    if(!empty(trim($_POST["confirm_password"]))){
        $confirm_password = trim($_POST["confirm_password"]);
    }

    // Check input errors before updating the database
    if(empty($username_err) && empty($email_err) && empty($password_err) && empty($new_password_err) && empty($confirm_password_err)){

        // Prepare an update statement
        $sql = "UPDATE users SET username=?, email=?, password=? WHERE id=?";

        if($stmt = mysqli_prepare($link, $sql)){

            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "sssi", $param_name, $param_email, $param_password, $param_id);

            // Set parameters
            $param_name = $username;
            $param_email = $email;
            $param_password = password_hash($new_password, PASSWORD_DEFAULT); // Hash the new password before storing
            $param_id = $id;

            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Password updated successfully. Destroy the session, and redirect to login page
                session_destroy();
                header("location: index.php");
                exit();
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
        }

        // Close statement
        mysqli_stmt_close($stmt);
    }

    // Close connection
    mysqli_close($link);
}
?>
