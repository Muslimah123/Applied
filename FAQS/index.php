<!DOCTYPE html>
<html>
<head>
	<title>FAQs Page</title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		body {
			font-family: Arial, Helvetica, sans-serif;
			font-size: 16px;
			line-height: 1.5;
			background-color: #f5f5f5;
			padding: 20px;
		}

		h1 {
			font-size: 32px;
			margin-bottom: 30px;
			text-align: center;
		}

		.faq {
			list-style: none;
			padding: 0;
			margin: 0;
			max-width: 800px;
			margin: 0 auto;
			background-color: #fff;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
			border-radius: 5px;
			overflow: hidden;
		}

		.question {
			font-weight: bold;
			cursor: pointer;
			padding: 15px;
			background-color: #f5f5f5;
			border-bottom: 1px solid #ddd;
		}

		.question:hover {
			background-color: #e1e1e1;
		}

		.answer {
			display: none;
			padding: 15px;
			border-bottom: 1px solid #ddd;
		}

		.answer:last-child {
			border-bottom: none;
		}
	</style>
</head>
<body>
	<h1>Frequently Asked Questions</h1>
	<ul class="faq">
		<li>
			<div class="question">What is Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is simply dummy text of the printing and typesetting industry.</div>
		</li>
		<li>
			<div class="question">Where can I get more information about Lorem Ipsum?</div>
			<div class="answer">There are many resources online where you can learn more about Lorem Ipsum, including Wikipedia.</div>
		</li>
		<li>
			<div class="question">Why do we use Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is used as a placeholder text in the design and printing industry.</div>
		</li>
        <li>
			<div class="question">What is Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is simply dummy text of the printing and typesetting industry.</div>
		</li>
		<li>
			<div class="question">Where can I get more information about Lorem Ipsum?</div>
			<div class="answer">There are many resources online where you can learn more about Lorem Ipsum, including Wikipedia.</div>
		</li>
		<li>
			<div class="question">Why do we use Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is used as a placeholder text in the design and printing industry.</div>
		</li>
        <li>
			<div class="question">What is Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is simply dummy text of the printing and typesetting industry.</div>
		</li>
		<li>
			<div class="question">Where can I get more information about Lorem Ipsum?</div>
			<div class="answer">There are many resources online where you can learn more about Lorem Ipsum, including Wikipedia.</div>
		</li>
		<li>
			<div class="question">Why do we use Lorem Ipsum?</div>
			<div class="answer">Lorem Ipsum is used as a placeholder text in the design and printing industry.</div>
		</li>
		<!-- Add more questions and answers here -->
	</ul>
	
	<script>
		const questions = document.querySelectorAll('.question');
		questions.forEach(function(question) {
			question.addEventListener('click', function() {
				const answer = question.nextElementSibling;
				if (answer.style.display === 'block') {
					answer.style.display = 'none';
				} else {
					answer.style.display = 'block';
				}
			});
		});
	</script>
</body>
</html>
