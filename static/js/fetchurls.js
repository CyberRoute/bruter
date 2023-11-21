function fetchUrls() {
	const xhr = new XMLHttpRequest();
	xhr.open("GET", "/consumer", true);
	xhr.onload = function () {
		if (this.status === 200) {
			// Parse JSON response
			const data = JSON.parse(this.responseText);

			// Get container element
			const container = document.getElementById("container");
			var bar = document.querySelector(".progress-bar");
			var speedElement = document.getElementById("data");
			// Clear loading message and append data
			container.innerHTML = "";
			data.Urls.forEach(url => {
				bar.style.width = url.progress + "%";
				speedElement.innerText = url.data;
				bar.innerText = url.progress.toFixed(0) + "%"; // format the percentage to one decimal place
				if (url.status === 200) { // only display 200 status codes in green
					container.innerHTML += `<p>${url.id} <a href="${url.path}" target="_blank">${url.path}</a> - <span style="color: green;"> http code: ${url.status} progress: ${url.progress} ${url.data}</span></p>`;
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
setInterval(fetchUrls, 1000);
