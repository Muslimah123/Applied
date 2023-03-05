<!DOCTYPE html>
<html>
<head>
	<title>Contact Us</title>
	<style>
		/* Style for the form container */
		.contact-container {
			max-width: 500px;
			margin: auto;
			padding: 20px;
			border: 1px solid #ccc;
			border-radius: 10px;
			background-color: #f2f2f2;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
		}
		/* Style for the form fields */
		input[type=text], select, textarea {
			width: 100%;
			padding: 12px;
			border: 1px solid #ccc;
			border-radius: 4px;
			box-sizing: border-box;
			margin-top: 6px;
			margin-bottom: 16px;
			resize: vertical;
		}
		input[type=submit] {
			background-color: #4CAF50;
			color: white;
			padding: 12px 20px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
		}
		input[type=submit]:hover {
			background-color: #45a049;
		}
		/* Style for the form labels */
		label {
			font-weight: bold;
		}
	</style>
</head>
<body>
	<div class="contact-container">
		<h2>Contact Us</h2>
		<form>
			<label for="name">Name</label>
			<input type="text" id="name" name="name" placeholder="Your name..">
			<label for="email">Email</label>
			<input type="text" id="email" name="email" placeholder="Your email..">
			<label for="subject">Subject</label>
			<select id="subject" name="subject">
				<option value="customer-service">Customer Service</option>
				<option value="sales">Sales</option>
				<option value="partnerships">Partnerships</option>
			</select>
			<label for="message">Message</label>
			<textarea id="message" name="message" placeholder="Write something.."></textarea>
			<input type="submit" value="Submit">
		</form>
	</div>
    <script src="custom.js"></script>
</body>
</html>
