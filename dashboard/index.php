<?php
session_start();
require_once('../register/db.php');

$id = $_SESSION['id'];
$sql = "SELECT username, email FROM users WHERE id = '$id'";
$result = mysqli_query($link, $sql);
$row = mysqli_fetch_assoc($result);
$username = $row['username'];
$email = $row['email'];


mysqli_close($link);
?>


<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible"
		content="IE=edge">
	<meta name="viewport"
		content="width=device-width,
				initial-scale=1.0">
	<title>Voice enabled FMS</title>
	<link rel="stylesheet"
		href="index.css">
	<link rel="stylesheet"
		href="responsive.css">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

	<style>
/* CSS */
 
.message {
  display: flex;
  align-items: center;
  background-color: #fff;
  border-radius: 25px;
  padding: 10px 20px;
  box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.25);
}

/* .circle {
  height: 50px;
  width: 50px;
  border-radius: 50%;
  background-color: #007bff;
  margin-right: 20px;
} */

 .fa-envelope {
  font-size: 24px;
  color: #007bff;
  margin-right: 20px;
} 

 
.dp {
  margin-right: 20px;
} 

 .dpicn {
  display: inline-block;
  position: relative;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  overflow: hidden;
} 

 .dpicn img {
  width: 100%;
  height: 100%;
  object-fit: cover;
} 

.username {
  font-size: 16px;
  color: #007bff;
  margin-left: 10px;
  position: absolute;
  bottom: 0;
}

#open-modal-btn {
  background-color: #007bff;
  color: #fff;
  border: none;
  border-radius: 5px;
  font-size: 16px;
  padding: 10px 20px;
  cursor: pointer;
  margin-left: auto;
}

/* Modal */
.modal {
  display: none; 
  position: fixed; 
  z-index: 1; 
  padding-top: 100px; 
  left: 0;
  top: 0;
  width: 100%; 
  height: 100%; 
  overflow: auto; 
  background-color: rgb(0,0,0); 
  background-color: rgba(0,0,0,0.4); 
}

.modal-content {
  background-color: #fefefe;
  margin: auto;
  padding: 20px;
  border: 1px solid #888;
  width: 50%;
  box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.25);
}

.close {
  color: #aaa;
  float: right;
  font-size: 28px;
  font-weight: bold;
}

.close:hover,
.close:focus {
  color: black;
  text-decoration: none;
  cursor: pointer;
}

 .resizable {
  overflow: auto;
  resize: both;
  max-height: 50vh;
  max-width: 50vw;
  padding: 10px;
  box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.25);
  animation-name: fadeIn;
  animation-duration: 0.5s;
  animation-fill-mode: both;
} 
.searchbar {
  display: flex;
  align-items: center;
  justify-content: center;
}

.searchbar input[type="text"] {
  width: 100%;
  padding: 12px 20px;
  margin: 8px 0;
  box-sizing: border-box;
  border: none;
  border-bottom: 2px solid #ccc;
  font-size: 16px;
  line-height: 30px;
}

.searchbar .searchbtn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 50px;
  height: 42px;
  background-color: blue;
  border: none;
  cursor: pointer;
  line-height:30px;
}

.searchbar .searchbtn i {
  font-size: 20px;
  color: white;
}



@keyframes fadeIn {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
form {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 20px;
}

label {
  display: block;
  font-size: 1.2em;
  margin-bottom: 10px;
}

input[type="text"],
input[type="email"],
input[type="password"] {
  padding: 10px;
  font-size: 1.2em;
  border-radius: 5px;
  border: none;
  margin-bottom: 20px;
  box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
  width: 100%;
}

input[type="submit"] {
  background-color: #4CAF50;
  color: white;
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-size: 1.2em;
}

input[type="submit"]:hover {
  background-color: #3e8e41;
}

input[type="text"]:focus,
input[type="email"]:focus,
input[type="password"]:focus {
  outline: none;
  box-shadow: 0 0 5px rgba(0, 0, 0, 0.5);
}
button[name="update-profile-btn"] {
  background-color: blue; /* Green */
  border: none;
  color: white;
  padding: 10px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 16px;
  margin: 4px 2px;
  cursor: pointer;
  border-radius: 5px;
}


	</style>
</head>

<body>

	<!-- for header part -->
	<header>

		<div class="logosec">
			<div class="logo"><p>Welcome,<?php echo $username; ?></p></div>
			<i class="fa fa-bars menuicn" id="menuicn"></i>
		</div>

		<div class="searchbar">
			<input type="text"
				placeholder="Search">
			<div class="searchbtn">
			<i class="fa fa-search srchicn"></i>
			</div>
		</div>
	
<div class="nav-bar">
  <div class="message">
    <div class="circle"></div>
    <i class="fa fa-envelope"></i>
   
    <div class="dp">
      
        <img src="https://media.geeksforgeeks.org/wp-content/uploads/20221210180014/profile-removebg-preview.png"
             class="dpicn"
             alt="dp">
       
    </div>
	

    <button id="open-modal-btn">Edit profile</button>
  </div>
</div>

<div id="myModal" class="modal">
  <div class="modal-content">
    <span class="close">&times;</span>
    <div class="modal-header">
      <h2>Update Profile</h2>
    </div>
    <div class="modal-body">
      <form method="POST" action="">
      
  <label for="name">Username:</label>
  <input type="text" id="name" name="name" value=""><br>

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" value=""><br>

  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br>

  <label for="new_password">New Password:</label>
  <input type="password" id="new_password" name="new_password"><br>

  <label for="confirm_password">Confirm Password:</label>
  <input type="password" id="confirm_password" name="confirm_password"><br>

  <button type="submit" name="update-profile-btn">Update Profile</button>
</form>

    </div>
  </div>
</div>

<!-- Modal -->
<!-- <div id="myModal" class="modal">
  <div class="modal-content ">
    <span class="close">&times;</span>
    <form method="POST" action="">
      <label for="name">Username:</label>
      <input type="text" id="name" name="name" value=""br>

      <label for="email">Email:</label>
      <input type="email" id="email" name="email" value=""><br>

      <label for="password">Password:</label>
      <input type="password" id="password" name="password"><br>

      <button type="submit" name="update-profile-btn">Update Profile</button>
    </form>
  </div>
</div> -->

<!-- JavaScript -->
<script>
  // Get the modal element
var modal = document.getElementById("myModal");

// Get the button that opens the modal
var btn = document.getElementById("open-modal-btn");

// Get the <span> element that closes the modal
var span = document.getElementsByClassName("close")[0];

// When the user clicks on the button, open the modal
btn.onclick = function() {
  modal.style.display = "block";
}

// When the user clicks on <span> (x), close the modal
span.onclick = function() {
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}

</script>



	</header>

	<div class="main-container">
		<div class="navcontainer">
			<nav class="nav">
				<div class="nav-upper-options">
					<div class="nav-option option1">
						<i class="fa fa-tachometer nav-img"></i>
						<h3> Dashboard</h3>
					</div>

					<div class="option2 nav-option">
						<i class="fa fa-bar-chart nav-img"></i>
						<h3> Sales</h3>
					</div>

					<div class="nav-option option3">
						<i class="fa fa-line-chart nav-img"></i>
						<h3> Report</h3>
					</div>

					<div class="nav-option option4">
						<i class="fa fa-shopping-bag nav-img"></i>
						<h3> Products</h3>
					</div>

					<div class="nav-option option5">
						<i class="fa fa-users nav-img"></i>
						<h3> Customers</h3>
					</div>

					<div class="nav-option option6">
						<i class="fa fa-cogs nav-img"></i>
						<h3> Settings</h3>
					</div>

					<div class="nav-option logout">
						<i class="fa fa-power-off nav-img"></i>
						<a href="../register/logout.php"><h3>Logout</h3></a>
					</div>

				</div>
			</nav>
		</div>
		<div class="main">

			<div class="searchbar2">
				<input type="text"
					name=""
					id=""
					placeholder="Search">
				<div class="searchbtn">
					<i class="fa fa-search srchicn"></i>
				</div>
			</div>

			<div class="box-container">

				<div class="box box1">
					<div class="text">
						<h2 class="topic-heading">Sales</h2>
						<h2 class="topic">View details</h2>
					</div>
</div>

					<div class="box box2">
					<div class="text">
						<h2 class="topic-heading">Report</h2>
						<h2 class="topic">View details</h2>
					</div>
				</div>
				<div class="box box3">
                    <div class="text">
                        <h2 class="topic-heading">Customers</h2>
                        <h2 class="topic">View details</h2>
                    </div>
			</div>

			<div class="box box4">
                    <div class="text">
                        <h2 class="topic-heading">Products</h2>
                        <h2 class="topic">View details</h2>
                    </div>
			</div>
		</div>
	</div>

	
	<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
	<script src="index.js"></script>
</body>

</html>

