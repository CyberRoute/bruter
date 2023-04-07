getLocation(ipAddress);

function getLocation(ipAddress) {
	$.getJSON('https://ipapi.co/' + ipAddress + '/json/', function (data) {
		var latitude = data.latitude;
		var longitude = data.longitude;

		var map = L.map('map').setView([latitude, longitude], 13);

		L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
			attribution: 'Map data &copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors',
			maxZoom: 4,
		}).addTo(map);

		var marker = L.marker([latitude, longitude]).addTo(map);
		marker.bindPopup("<b>Destination IP Address:</b> " + ipAddress).openPopup();

		// get location of sourceIp
		$.getJSON('https://ipapi.co/json/', function (data) {
			var sourceLatitude = data.latitude;
			var sourceLongitude = data.longitude;
			var sourceIp = data.ip;

			// add marker for sourceIp with different color
			var sourceIpMarker = L.marker([sourceLatitude, sourceLongitude], {
				icon: L.icon({
					iconUrl: 'http://maps.google.com/mapfiles/ms/icons/red-dot.png'
				})
			}).addTo(map);
			sourceIpMarker.bindPopup("<b>Source IP Address:</b> " + sourceIp).openPopup();

			// add line between source and destination markers
			var line = L.polyline([
				[sourceLatitude, sourceLongitude],
				[latitude, longitude]
			], {
				color: 'green'
			}).addTo(map);
			line.bindPopup("<b>Route:</b> " + sourceIp + " → " + ipAddress).openPopup();
		});
	}).fail(function () {
		alert('Invalid IP address.');
	});
}