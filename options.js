document.addEventListener('DOMContentLoaded', () => {
  const groqInput = document.getElementById('groqKey');
  const vtInput = document.getElementById('vtKey');
  const modelInput = document.getElementById('model');
  const saveBtn = document.getElementById('saveBtn');
  const statusTxt = document.getElementById('status');
  const defaultModel = 'qwen/qwen3.8-27b';

  chrome.storage.local.get(['groqKey', 'vtKey', 'model'], (result) => {
    if (result.groqKey) groqInput.value = result.groqKey;
    if (result.vtKey) vtInput.value = result.vtKey;
    modelInput.value = result.model || defaultModel;
  });

  saveBtn.addEventListener('click', () => {
    const groqVal = groqInput.value.trim();
    const vtVal = vtInput.value.trim();
    const modelVal = modelInput.value.trim();

    if (!modelVal) {
      statusTxt.innerText = "Enter a Groq model name.";
      return;
    }

    chrome.storage.local.set({ groqKey: groqVal, vtKey: vtVal, model: modelVal }, () => {
      statusTxt.innerText = "Settings saved successfully!";
      setTimeout(() => { statusTxt.innerText = ""; }, 3000);
    });
  });
});