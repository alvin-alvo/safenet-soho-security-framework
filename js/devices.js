window.onload = function() {
  const devices = [
    { name: "Work-Laptop", ip: "10.0.0.2", group: "Admins", status: "Online" },
    { name: "Smart-TV", ip: "10.0.0.3", group: "IoT", status: "Offline" },
    { name: "Personal-Phone", ip: "10.0.0.4", group: "Guests", status: "Online" }
  ];

  const table = document.getElementById("deviceTable");
  devices.forEach(d => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${d.name}</td>
      <td>${d.ip}</td>
      <td>${d.group}</td>
      <td style="color:${d.status === 'Online' ? 'green' : 'red'};">${d.status}</td>`;
    table.appendChild(row);
  });
};