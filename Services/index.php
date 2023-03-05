<!DOCTYPE html>
<html>
<head>
	<title>Services</title>
	<style>
		/* General styles */
			/* Style for service list */
            .services {
			display: flex;
			flex-wrap: wrap;
			margin: 0;
			padding: 0;
			list-style: none;
			justify-content: center;
		}

		/* Style for individual service */
		.service {
			display: flex;
			flex-direction: column;
			align-items: center;
			margin: 20px;
			padding: 20px;
			background-color: #f9f9f9;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
			transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
			max-width: 400px;
			width: 100%;
			position: relative;
		}

		/* Style for service image */
		.service-image {
			margin-bottom: 20px;
			max-width: 100%;
			height: auto;
			border-radius: 10px;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
			transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
			position: relative;
			z-index: 1;
		}

		/* Hover style for service image */
		.service-image:hover {
			transform: scale(1.1);
			box-shadow: 0 15px 20px rgba(0, 0, 0, 0.4);
		}

		/* Style for service title */
		.service-title {
			font-size: 2.5rem;
			margin: 0;
			margin-bottom: 10px;
			text-align: center;
			color: #333;
			font-weight: bold;
			text-transform: uppercase;
			letter-spacing: 1px;
			position: relative;
			z-index: 2;
		}

		/* Style for service description */
		.service-description {
			font-size: 1.2rem;
			line-height: 1.5;
			margin: 0;
			margin-bottom: 20px;
			text-align: justify;
			color: #555;
			position: relative;
			z-index: 2;
		}

		/* Style for service button */
		.service-button {
			font-size: 1.2rem;
			padding: 10px 20px;
			background-color: #555;
			color: #fff;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			transition: background-color 0.2s ease-in-out;
			position: relative;
			z-index: 2;
			text-transform: uppercase;
			letter-spacing: 1px;
			font-weight: bold;
		}

		/* Hover style for service button */
		.service-button:hover {
			background-color: #333;
		}

		/* Hover style for service */
		.service:hover {
			transform: translateY(-10px);
			box-shadow: 0 15px 20px rgba(0, 0, 0, 0.4);
		}
		@media screen and (max-width: 768px) {
			.services {
				padding: 20px;
			}
			.service {
				flex-basis: 45%;
			}
		}
	</style>
</head>
<body>

	<header>
		<h1>Our Services</h1>
	</header>

	<main>
		<section>
			<h2>Service 1</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 1 Image">
				<h3 class="service-title">Service 1 Title</h3>
				<p class="service-description">Service 1 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>

		<section>
			<h2>Service 2</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 2 Image">
				<h3 class="service-title">Service 2 Title</h3>
				<p class="service-description">Service 2 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>

		<section>
			<h2>Service 3</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 3 Image">
				<h3 class="service-title">Service 3 Title</h3>
				<p class="service-description">Service 3 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>
        <section>
			<h2>Service 1</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 1 Image">
				<h3 class="service-title">Service 1 Title</h3>
				<p class="service-description">Service 1 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>

		<section>
			<h2>Service 2</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 2 Image">
				<h3 class="service-title">Service 2 Title</h3>
				<p class="service-description">Service 2 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>

		<section>
			<h2>Service 3</h2>
			<div class="service">
				<img class="service-image" src="https://via.placeholder.com/400x200" alt="Service 3 Image">
				<h3 class="service-title">Service 3 Title</h3>
				<p class="service-description">Service 3 description goes here. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquet, ex vel suscipit lacinia, massa tortor faucibus nulla, quis elementum ex ante eu velit. Suspendisse et magna ultrices, sagittis eros sit amet, cursus lacus. Donec tristique, ex id molestie suscipit, sapien nisl ultrices est, a porttitor turpis elit et elit. Curabitur pulvinar orci ac dui fermentum, ut ultricies dolor convallis.</p>
				<button class="service-button">Learn More</button>
			</div>
		</section>
	</main>

	<footer>
		<p>&copy; 
    </footer>

	<script>
		// Add event listeners to service buttons
		const serviceButtons = document.querySelectorAll('.service-button');
		serviceButtons.forEach(button => {
			button.addEventListener('click', () => {
				alert('This service is not available yet.');
			});
		});
	</script>
</body>
</html>

