document.addEventListener('DOMContentLoaded', () => {
  const groqInput = document.getElementById('groqKey');
  const vtInput = document.getElementById('vtKey');
  const saveBtn = document.getElementById('saveBtn');
  const statusTxt = document.getElementById('status');

  chrome.storage.local.get(['groqKey', 'vtKey'], (result) => {
    if (result.groqKey) groqInput.value = result.groqKey;
    if (result.vtKey) vtInput.value = result.vtKey;
  });

  saveBtn.addEventListener('click', () => {
    const groqVal = groqInput.value.trim();
    const vtVal = vtInput.value.trim();

    chrome.storage.local.set({ groqKey: groqVal, vtKey: vtVal }, () => {
      statusTxt.innerText = "Keys saved successfully!";
      setTimeout(() => { statusTxt.innerText = ""; }, 3000);
    });
  });
});