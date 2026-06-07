const form = document.querySelector("#uploadForm");
const submitButton = document.querySelector("#submitButton");
const submitLabel = document.querySelector("#submitLabel");
const submitLoader = document.querySelector("#submitLoader");
const responseSection = document.querySelector("#response");
const resultValue = document.querySelector("#resultValue");
const base64Value = document.querySelector("#base64Value");
const downloadPdfLink = document.querySelector("#downloadPdfLink");
const errorBox = document.querySelector("#error");
const userBar = document.querySelector("#userBar");
const userGreeting = document.querySelector("#userGreeting");
const userMenuButton = document.querySelector("#userMenuButton");
const userAvatar = document.querySelector("#userAvatar");
const userDropdown = document.querySelector("#userDropdown");
const logoutButton = document.querySelector("#logoutButton");

let pdfObjectUrl;
let keycloak;

setupDropzone("firstFile", "firstFileName");
setupDropzone("secondFile", "secondFileName");
initKeycloak();

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const formData = new FormData(form);
    submitButton.disabled = true;
    submitLabel.textContent = "Wysylanie...";
    submitLoader.hidden = false;
    errorBox.hidden = true;
    responseSection.hidden = true;
    downloadPdfLink.hidden = true;
    revokePdfObjectUrl();

    try {
        await refreshToken();

        const response = await fetch("/api/files/process", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${keycloak.token}`
            },
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        resultValue.textContent = data.result ?? "";
        base64Value.value = data.pdfFileInBase64 ?? "";
        preparePdfDownload(data.pdfFileInBase64);
        responseSection.hidden = false;
    } catch (error) {
        errorBox.textContent = `Nie udalo sie wyslac plikow: ${error.message}`;
        errorBox.hidden = false;
    } finally {
        submitButton.disabled = false;
        submitLabel.textContent = "Wyslij";
        submitLoader.hidden = true;
    }
});

window.addEventListener("beforeunload", revokePdfObjectUrl);
document.addEventListener("click", closeUserDropdownOnOutsideClick);
userMenuButton.addEventListener("click", toggleUserDropdown);
logoutButton.addEventListener("click", () => keycloak.logout());

async function initKeycloak() {
    setFormEnabled(false);

    if (typeof Keycloak === "undefined") {
        showAuthError("Nie udalo sie zaladowac adaptera Keycloak z localhost:8085.");
        return;
    }

    keycloak = new Keycloak({
        url: "http://localhost:8085",
        realm: "test",
        clientId: "test-public"
    });

    try {
        await keycloak.init({
            onLoad: "login-required",
            checkLoginIframe: false
        });

        renderAuthenticatedUser();
        setFormEnabled(true);
    } catch (error) {
        showAuthError(`Nie udalo sie zalogowac przez Keycloak: ${error.message ?? error}`);
    }
}

async function refreshToken() {
    try {
        await keycloak.updateToken(30);
    } catch (error) {
        await keycloak.login();
        throw error;
    }
}

function renderAuthenticatedUser() {
    const preferredName =  keycloak.tokenParsed?.name
        ?? keycloak.tokenParsed?.email
        ?? keycloak.tokenParsed?.preferred_username
        ?? "zalogowany uzytkownik";

    userGreeting.innerHTML = `Cześć<br><strong>${preferredName}</strong>`;
    userAvatar.textContent = preferredName.trim().charAt(0).toUpperCase();
    userAvatar.style.backgroundColor = getUserColor(preferredName);
    userBar.hidden = false;
}

function toggleUserDropdown(event) {
    event.stopPropagation();

    const isOpen = userDropdown.hidden;
    userDropdown.hidden = !isOpen;
    userMenuButton.setAttribute("aria-expanded", String(isOpen));
}

function closeUserDropdownOnOutsideClick(event) {
    if (userBar.hidden || userDropdown.hidden || userMenuButton.contains(event.target) || userDropdown.contains(event.target)) {
        return;
    }

    userDropdown.hidden = true;
    userMenuButton.setAttribute("aria-expanded", "false");
}

function getUserColor(name) {
    let hash = 0;

    for (let index = 0; index < name.length; index += 1) {
        hash = ((hash << 5) - hash) + name.charCodeAt(index);
        hash |= 0;
    }

    const hue = Math.abs(hash) % 360;
    return `hsl(${hue}, 82%, 48%)`;
}

function showAuthError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
}

function setFormEnabled(isEnabled) {
    submitButton.disabled = !isEnabled;
    submitLabel.textContent = isEnabled ? "Wyslij" : "Logowanie...";
}

function setupDropzone(inputId, fileNameId) {
    const input = document.querySelector(`#${inputId}`);
    const dropzone = input.closest(".dropzone");
    const fileName = document.querySelector(`#${fileNameId}`);

    input.addEventListener("change", () => {
        updateFileName(input, fileName);
    });

    ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.add("is-dragging");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.remove("is-dragging");
        });
    });

    dropzone.addEventListener("drop", (event) => {
        const files = event.dataTransfer.files;

        if (files.length === 0) {
            return;
        }

        input.files = files;
        updateFileName(input, fileName);
    });
}

function updateFileName(input, fileName) {
    fileName.textContent = input.files.length > 0 ? input.files[0].name : "Nie wybrano pliku";
}

function preparePdfDownload(base64Value) {
    if (!base64Value) {
        return;
    }

    const pdfBytes = base64ToUint8Array(base64Value);
    const pdfBlob = new Blob([pdfBytes], { type: "application/pdf" });
    pdfObjectUrl = URL.createObjectURL(pdfBlob);

    downloadPdfLink.href = pdfObjectUrl;
    downloadPdfLink.hidden = false;
}

function base64ToUint8Array(base64Value) {
    const binary = atob(base64Value);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
}

function revokePdfObjectUrl() {
    if (pdfObjectUrl) {
        URL.revokeObjectURL(pdfObjectUrl);
        pdfObjectUrl = undefined;
    }
}
