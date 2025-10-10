window.onload = function() {
  const canvas = document.getElementById("networkGraph");
  const ctx = canvas.getContext("2d");

  // Example mock network visualization
  const devices = [
    { x: 100, y: 200, name: "Laptop" },
    { x: 300, y: 100, name: "Phone" },
    { x: 500, y: 250, name: "IoT Sensor" }
  ];

  // Draw connections
  ctx.strokeStyle = "green";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(devices[0].x, devices[0].y);
  ctx.lineTo(devices[1].x, devices[1].y);
  ctx.lineTo(devices[2].x, devices[2].y);
  ctx.stroke();

  // Draw device nodes
  ctx.fillStyle = "#3b82f6";
  devices.forEach(d => {
    ctx.beginPath();
    ctx.arc(d.x, d.y, 20, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "#111827";
    ctx.fillText(d.name, d.x - 25, d.y + 40);
    ctx.fillStyle = "#3b82f6";
  });
};