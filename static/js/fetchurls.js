function fetchUrls() {
	const xhr = new XMLHttpRequest();
	xhr.open("GET", "/consumer", true);
	xhr.onload = function() {
		if (this.status === 200) {
			// Parse JSON response
			const data = JSON.parse(this.responseText);

			// Get container element
			const container = document.getElementById("container");
			var bar = document.querySelector(".progress-bar");

			// Clear loading message and append data
			container.innerHTML = "";
			data.Urls.forEach(url => {
				bar.style.width = url.progress + "%";
				bar.innerText = url.progress + "%";
				if (url.status === 200 || url.status === 403) { // only display 200 and 403 status codes
					const color = url.status === 200 ? "green" : "red";

					container.innerHTML += `<p>${url.path} - <span style="color: ${color};">${url.status}</span></p>`;
				}
			});
		} else {
			console.error("Error fetching data");
		}
	}
	xhr.send();
}

// Call fetchUrls() when page is loaded
window.onload = fetchUrls;
setInterval(fetchUrls, 5000);