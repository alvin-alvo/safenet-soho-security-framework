function savePolicy() {
  const content = document.getElementById("policyEditor").value;
  alert("Policy saved and applied:\n\n" + content);
}

function revertPolicy() {
  document.getElementById("policyEditor").value =
`policies:
  - group: admins
    access: full
  - group: guests
    access: restricted`;
  alert("Reverted to last saved policy.");
}