const analyzeForm = document.getElementById("analyze-form");
if (analyzeForm) {
  analyzeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.getElementById("analyze-btn");
    const resultBox = document.getElementById("result");
    button.disabled = true;
    button.textContent = "Analyzing…";
    resultBox.classList.remove("hidden");
    resultBox.textContent = "Checking indicators. This may take a moment if the AI API is enabled.";
    try {
      const response = await fetch("/analyze", { method: "POST", body: new FormData(analyzeForm) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analysis failed.");
      renderResult(resultBox, data);
    } catch (error) {
      resultBox.textContent = error.message;
    } finally {
      button.disabled = false;
      button.innerHTML = 'Analyze content <span>→</span>';
    }
  });
}
function renderResult(box, data) {
  box.replaceChildren();
  const top = document.createElement("div");
  top.className = "result-top";
  const heading = document.createElement("h3");
  heading.textContent = "Analysis result";
  const pill = document.createElement("span");
  pill.className = "pill " + String(data.risk_level || "inconclusive").toLowerCase();
  pill.textContent = data.risk_level || "Inconclusive";
  top.append(heading, pill);
  box.append(top);
  addText(box, "Category", data.category);
  addText(box, "Explanation", data.explanation);
  addText(box, "Warning signs", (data.indicators || []).length ? data.indicators.join(" · ") : "No matching indicators found by the local rules.");
  if (data.url_checks) {
    addText(box, "URL check", data.url_checks.explanation);
    if (data.url_checks.host) addText(box, "Parsed host", data.url_checks.host);
  }
  if (data.ai_analysis) addText(box, "Gemma 4 analysis", data.ai_analysis);
  if (data.image_note) addText(box, "Image handling", data.image_note);
  if (data.recommended_actions?.length) {
    const title = document.createElement("strong"); title.textContent = "Recommended actions"; box.append(title);
    const ul = document.createElement("ul");
    data.recommended_actions.forEach(item => { const li = document.createElement("li"); li.textContent = item; ul.append(li); });
    box.append(ul);
  }
  addText(box, "Important", data.disclaimer);
}
function addText(parent, label, value) {
  if (!value) return;
  const p = document.createElement("p");
  const strong = document.createElement("strong"); strong.textContent = label + ": ";
  p.append(strong, document.createTextNode(String(value)));
  parent.append(p);
}
const chatForm = document.getElementById("chat-form");
if (chatForm) {
  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("chat-message");
    const box = document.getElementById("chat-answer");
    const button = chatForm.querySelector("button");
    if (!input.value.trim()) return;
    button.disabled = true; box.classList.remove("hidden"); box.textContent = "Thinking…";
    try {
      const response = await fetch("/chat", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:input.value})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Request failed.");
      box.textContent = data.answer;
    } catch (err) { box.textContent = err.message; }
    finally { button.disabled = false; }
  });
}
const clearButton = document.getElementById("clear-history");
if (clearButton) {
  clearButton.addEventListener("click", async () => {
    if (!confirm("Delete all locally stored scan history?")) return;
    const response = await fetch("/history/clear", {method:"POST"});
    if (response.ok) location.reload();
    else alert("Could not clear history.");
  });
}


// Update the custom screenshot upload control with the selected filename.
const imageInput = document.getElementById("image");
const imageFileName = document.getElementById("image-file-name");
if (imageInput && imageFileName) {
  imageInput.addEventListener("change", () => {
    const file = imageInput.files && imageInput.files[0];
    imageFileName.textContent = file ? file.name : "No file selected";
    imageFileName.classList.toggle("has-file", Boolean(file));
  });
}
