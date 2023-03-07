<!-- <!DOCTYPE html>
<html>
<head>
	<title>Financial Management System - Services</title>
	<link rel="stylesheet" href="index.css">
</head>
<body>
	<h1>Our Services</h1>
	
	<ul>
		<li><a href="#budget">Budget Tracking</a></li>
		<li><a href="#expense">Expense Management</a></li>
		<li><a href="#investment">Investment Tracking</a></li>
		<li><a href="#balances">Account Balances</a></li>
		<li><a href="#history">Transaction History</a></li>
	</ul>
	
	<hr>
	
	<h2 id="budget">Budget Tracking</h2>
	<p>With budget tracking, you can keep track of your monthly expenses and income.</p>
	<h3>Using Voice Commands</h3>
	<p>To add an expense, say "Add expense" followed by the amount and the category. For example, "Add expense 50 dollars for groceries." To add income, say "Add income" followed by the amount and a description. For example, "Add income 100 dollars from my paycheck."</p>
	<h3>Requirements</h3>
	<p>Requires a linked bank account or credit card account.</p>
	
	<hr>
	
	<h2 id="expense">Expense Management</h2>
	<p>With expense management, you can categorize and track your expenses.</p>
	<h3>Using Voice Commands</h3>
	<p>To add an expense, say "Add expense" followed by the amount and the category. For example, "Add expense 50 dollars for groceries."</p>
	<h3>Requirements</h3>
	<p>Requires a linked bank account or credit card account.</p>
	
	<hr>
	
	<h2 id="investment">Investment Tracking</h2>
	<p>With investment tracking, you can monitor the performance of your investments.</p>
	<h3>Using Voice Commands</h3>
	<p>To add an investment, say "Add investment" followed by the name, the amount and the date. For example, "Add investment Apple stock 1000 dollars on January 1st."</p>
	<h3>Requirements</h3>
	<p>Requires a linked investment account.</p>
	
	<hr>
	
	<h2 id="balances">Account Balances</h2>
	<p>With account balances, you can check the balances of your linked accounts.</p>
	<h3>Using Voice Commands</h3>
	<p>To check your account balances, say "What is my balance?"</p>
	<h3>Requirements</h3>
	<p>Requires linked bank account, credit card account or investment account.</p>
	
	<hr>
	
	<h2 id="history">Transaction History</h2>
	<p>With transaction history, you can view a list of your past transactions.</p>
	<h3>Using Voice Commands</h3>
	<p>To view your transaction history, say "Show my transaction history."</p>
	<h3>Requirements</h3>
	<p>Requires a linked bank account or credit card account.</p>
</body>
</html>
 -->
 <!DOCTYPE html>
<html>
<head>
	<title>Financial Management System - Services</title>
	<link rel="stylesheet" href="index.css">
</head>
<body>
	<h1>Our Services</h1>
	
	<div class="services-container">
		<div class="service">
			<h2>Budget Tracking</h2>
			<p>Keep track of your monthly expenses and income.</p>
			<button class="modal-button">View Details</button>
			<div class="modal">
				<div class="modal-content">
					<span class="close-button">&times;</span>
					<div class="service-details">
					<h3>Budget Tracking</h3>
					<p>With budget tracking, you can keep track of your monthly expenses and income using voice commands. To add an expense, say "Add expense" followed by the amount and the category. For example, "Add expense 50 dollars for groceries." To add income, say "Add income" followed by the amount and a description. For example, "Add income 100 dollars from my paycheck." Budget tracking requires a linked bank account or credit card account.</p>
</div>
				</div>
			</div>
		</div>
		
		<div class="service">
			<h2>Expense Management</h2>
			<p>Categorize and track your expenses.</p>
			<button class="modal-button">View Details</button>
			<div class="modal">
				<div class="modal-content">
					<span class="close-button">&times;</span>
					<div class="service-details">
					<h3>Expense Management</h3>
					<p>With expense management, you can categorize and track your expenses using voice commands. To add an expense, say "Add expense" followed by the amount and the category. For example, "Add expense 50 dollars for groceries." Expense management requires a linked bank account or credit card account.</p>
</div>
				</div>
			</div>
		</div>
		
		<div class="service">
			<h2>Investment Tracking</h2>
			<p>Monitor the performance of your investments.</p>
			<button class="modal-button">View Details</button>
			<div class="modal">
				<div class="modal-content">
					<span class="close-button">&times;</span>
					<div class="service-details">
					<h3>Investment Tracking</h3>
					<p>With investment tracking, you can monitor the performance of your investments using voice commands. To add an investment, say "Add investment" followed by the name, the amount and the date. For example, "Add investment Apple stock 1000 dollars on January 1st." Investment tracking requires a linked investment account.</p>
				</div>
</div>
			</div>
		</div>
		
		<div class="service">
			<h2>Account Balances</h2>
			<p>Check the balances of your linked accounts.</p>
			<button class="modal-button">View Details</button>
			<div class="modal">
				<div class="modal-content">
					<span class="close-button">&times;</span>
					<div class="service-details">
					<h3>Account Balances</h3>
					<p>With account balances, you can check the balances of your linked bank accounts, credit card accounts or investment accounts using voice commands. To check your account balances, say "What is my balance?"</p>
				</div>
</div>
			</div>
		</div>
		
	<div class="service">
  <h2>Transaction History</h2>
  <p>View a list of your past transactions.</p>
  <button class="modal-button">View Details</button>
  <div class="modal">
    <div class="modal-content">
      <span class="close-button">&times;</span>
	  <div class="service-details">
      <h3>Transaction History</h3>
      <p>With transaction history, you can view a list of your past transactions.</p>
      <h4>Using Voice Commands</h4>
      <p>To view your transaction history, say "Show my transaction history."</p>
      <h4>Requirements</h4>
      <p>Requires a linked bank account or credit card account.</p>
  </div>
</div>
       </div>
</div>
</div>
<script>
	// get all modal buttons and modal dialogs
var modalButtons = document.querySelectorAll('.modal-button');
var modalDialogs = document.querySelectorAll('.modal');

// add click event listener to each modal button
modalButtons.forEach(function(modalButton, index) {
  // add click event listener to modal button
  modalButton.addEventListener('click', function() {
    // display the modal dialog
    modalDialogs[index].style.display = 'block';
  });

  // add click event listener to close button
  var closeButton = modalDialogs[index].querySelector('.close-button');
  closeButton.addEventListener('click', function() {
    // hide the modal dialog
    modalDialogs[index].style.display = 'none';
  });

  // add click event listener to modal content
  var modalContent = modalDialogs[index].querySelector('.modal-content');
  modalContent.addEventListener('click', function(event) {
    // if the user clicks outside of the modal content, hide the modal dialog
    if (event.target == modalDialogs[index]) {
      modalDialogs[index].style.display = 'none';
    }
  });
});

</script>
</body>
</html>
