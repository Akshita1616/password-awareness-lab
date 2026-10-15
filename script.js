
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const clearBtn = document.getElementById("clearBtn");
const breachBtn = document.getElementById("breachBtn");

const meterFill = document.getElementById("meterFill");
const meter = document.getElementById("strengthMeter");
const strengthText = document.getElementById("strengthText");
const scoreElement = document.getElementById("score");
const advice = document.getElementById("advice");
const breachResult = document.getElementById("breachResult");

let requestNumber = 0;

const requirementIds = [
  "req-length",
  "req-upper",
  "req-lower",
  "req-number",
  "req-symbol",
  "req-long"
];

function setRequirement(id, passed) {
  const element = document.getElementById(id);
  element.classList.toggle("pass", passed);
  element.querySelector(".req-icon").textContent = passed ? "✓" : "○";
}

function hasCommonPattern(password) {
  const value = password.toLowerCase();

  const commonPasswords = [
    "password", "password123", "12345678",
    "123456789", "qwerty", "admin", "letmein",
    "iloveyou", "welcome", "abc123"
  ];

  if (commonPasswords.includes(value)) return true;

  // Detect repeated sequences and keyboard patterns.
  if (/(.)\1{3,}/i.test(password)) return true;
  if (/^(0123|1234|2345|3456|4567|5678|6789)+$/.test(password)) {
    return true;
  }
  if (/^(qwerty|asdf|zxcv)+$/i.test(password)) return true;

  return false;
}

function analyzePassword() {
  const password = passwordInput.value;
  const length = password.length;

  const checks = {
    "req-length": length >= 12,
    "req-upper": /[A-Z]/.test(password),
    "req-lower": /[a-z]/.test(password),
    "req-number": /[0-9]/.test(password),
    "req-symbol": /[^A-Za-z0-9]/.test(password),
    "req-long": length >= 16
  };

  Object.entries(checks).forEach(([id, passed]) => {
    setRequirement(id, passed);
  });

  if (!password) {
    scoreElement.textContent = "0";
    meterFill.style.width = "0%";
    meter.setAttribute("aria-valuenow", "0");
    strengthText.textContent = "Not assessed";
    strengthText.style.color = "var(--muted)";
    advice.textContent =
      "Enter a sample password to begin your analysis.";
    return;
  }

  let score = 0;

  // Educational heuristic, not a cryptographic guarantee.
  score += Math.min(length / 20, 1) * 40;
  score += (checks["req-upper"] ? 10 : 0);
  score += (checks["req-lower"] ? 10 : 0);
  score += (checks["req-number"] ? 10 : 0);
  score += (checks["req-symbol"] ? 10 : 0);
  score += (checks["req-long"] ? 10 : 0);

  const common = hasCommonPattern(password);
  const predictable =
    /password|qwerty|admin|welcome|letmein|iloveyou/i.test(password);

  if (common) score -= 35;
  if (predictable && !common) score -= 20;

  // Discourage short passwords and long repeated characters.
  if (length < 8) score = Math.min(score, 25);
  if (/(.)\1{3,}/i.test(password)) score -= 15;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let label;
  let color;
  let message;

  if (common || score < 30) {
    label = "Weak";
    color = "var(--red)";
    message = common
      ? "This password uses a common password or predictable pattern. Choose something unique and longer."
      : "Try a longer, less predictable password. Avoid personal details and familiar sequences.";
  } else if (score < 50) {
    label = "Fair";
    color = "var(--yellow)";
    message = "Add more length and avoid predictable words, patterns, and repeated characters.";
  } else if (score < 75) {
    label = "Moderate";
    color = "#a3b4ff";
    message = "A reasonable start, but more length and uniqueness can improve it.";
  } else {
    label = "Strong";
    color = "var(--green)";
    message = "This sample meets several strength criteria. A high score does not guarantee that it is safe or absent from breach datasets.";
  }

  scoreElement.textContent = String(score);
  meterFill.style.width = `${score}%`;
  meterFill.style.background = color;
  meter.setAttribute("aria-valuenow", String(score));
  strengthText.textContent = label;
  strengthText.style.color = color;
  advice.textContent = message;
}

function showBreachResult(type, title, message) {
  breachResult.className = `breach-result ${type}`;
  breachResult.replaceChildren();

  const icon = document.createElement("div");
  icon.className = "result-icon";
  icon.textContent =
    type === "found" ? "!" :
    type === "clear" ? "✓" :
    type === "error" ? "!" : "i";

  const content = document.createElement("div");
  const heading = document.createElement("strong");
  const paragraph = document.createElement("p");

  heading.textContent = title;
  paragraph.textContent = message;

  content.append(heading, paragraph);
  breachResult.append(icon, content);
}

async function sha1Hex(value) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Secure cryptography is unavailable. Open this site using HTTPS or localhost.");
  }

  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-1", bytes);

  return Array.from(new Uint8Array(hash))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkBreach() {
  const password = passwordInput.value;
  const currentRequest = ++requestNumber;

  if (!password) {
    showBreachResult(
      "error",
      "Password required",
      "Enter a fictional sample password before starting the check."
    );
    passwordInput.focus();
    return;
  }

  breachBtn.disabled = true;
  breachBtn.textContent = "Checking...";
  showBreachResult(
    "",
    "Checking database",
    "Calculating a hash and requesting matching hash prefixes..."
  );

  try {
    // The complete password is never sent to the API.
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        method: "GET",
        headers: {
          "Add-Padding": "true"
        },
        cache: "no-store"
      }
    );

    if (!response.ok) {
      throw new Error(
        `Breach service returned HTTP ${response.status}.`
      );
    }

    const body = await response.text();

    // A newer request should not overwrite its result.
    if (currentRequest !== requestNumber) return;

    let occurrences = 0;
    let matched = false;

    for (const line of body.split(/\r?\n/)) {
      const separator = line.indexOf(":");
      if (separator === -1) continue;

      const returnedSuffix = line.slice(0, separator).trim();
      const countText = line.slice(separator + 1).trim();

      if (returnedSuffix.toUpperCase() === suffix) {
        const count = Number(countText);

        if (Number.isSafeInteger(count) && count >= 0) {
          occurrences = count;
          matched = count > 0;
        }
        break;
      }
    }

    if (matched) {
      showBreachResult(
        "found",
        "⚠ Password found in breach data",
        `This hash matched a password reported ${occurrences.toLocaleString()} time(s) in the dataset. Do not use this password.`
      );
    } else {
      showBreachResult(
        "clear",
        "No match returned",
        "No positive match was returned by this lookup. This does not prove the password is safe or has never been exposed."
      );
    }
  } catch (error) {
    if (currentRequest !== requestNumber) return;

    showBreachResult(
      "error",
      "Check could not be completed",
      `${error.message || "A network error occurred."} Check your connection and try again.`
    );
  } finally {
    if (currentRequest === requestNumber) {
      breachBtn.disabled = false;
      breachBtn.innerHTML = "<span>⌕</span> Check breach database";
    }
  }
}

togglePassword.addEventListener("click", () => {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  togglePassword.textContent = isHidden ? "Hide" : "Show";
  togglePassword.setAttribute("aria-pressed", String(isHidden));
  togglePassword.setAttribute(
    "aria-label",
    isHidden ? "Hide password" : "Show password"
  );
});

passwordInput.addEventListener("input", () => {
  // Invalidate any older result when the sample changes.
  requestNumber++;
  analyzePassword();

  showBreachResult(
    "",
    "Ready to check",
    "Your sample has changed. Run the breach check to analyze this version."
  );
});

breachBtn.addEventListener("click", checkBreach);

clearBtn.addEventListener("click", () => {
  requestNumber++;
  passwordInput.value = "";
  passwordInput.type = "password";
  togglePassword.textContent = "Show";
  togglePassword.setAttribute("aria-pressed", "false");
  togglePassword.setAttribute("aria-label", "Show password");

  analyzePassword();

  requirementIds.forEach(id => setRequirement(id, false));

  showBreachResult(
    "",
    "Ready to check",
    "Enter a sample password and start the check."
  );

  passwordInput.focus();
});

analyzePassword();
