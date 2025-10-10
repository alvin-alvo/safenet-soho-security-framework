window.onload = function() {
  const logs = [
    "[12:45:01] Policy change detected.",
    "[12:45:05] Applying new configuration for 'work-laptop'.",
    "[12:45:09] Peer 'personal-phone' successfully connected.",
    "[12:46:00] Network verified. Status: PROTECTED."
  ];

  const logArea = document.getElementById("logArea");
  logs.forEach(line => {
    const p = document.createElement("div");
    p.textContent = line;
    logArea.appendChild(p);
  });
};