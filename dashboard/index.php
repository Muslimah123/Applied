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
</head>

<body>

	<!-- for header part -->
	<header>

		<div class="logosec">
			<div class="logo">Voice Enabled FMS</div>
			<i class="fa fa-bars menuicn" id="menuicn"></i>
		</div>

		<div class="searchbar">
			<input type="text"
				placeholder="Search">
			<div class="searchbtn">
			<i class="fa fa-search srchicn"></i>
			</div>
		</div>

		<div class="message">
			<div class="circle"></div>
			<i class="fa fa-envelope"></i>
			<div class="dp">
				<i class="fa fa-user-circle-o dpicn"><img src=
"https://media.geeksforgeeks.org/wp-content/uploads/20221210180014/profile-removebg-preview.png"
                    class="dpicn"
                    alt="dp"></i>
			</div>
		</div>

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
						<h2 class="topic-heading">Profit</h2>
						<h2 class="topic">View details</h2>
					</div>
</div>

					<div class="box box2">
					<div class="text">
						<h2 class="topic-heading">Sales</h2>
						<h2 class="topic">View details</h2>
					</div>
				</div>
				<div class="box box3">
                    <div class="text">
                        <h2 class="topic-heading">Expenses</h2>
                        <h2 class="topic">View details</h2>
                    </div>
			</div>

			
		</div>
	</div>

	
	<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
	<script src="index.js"></script>
</body>

</html>

