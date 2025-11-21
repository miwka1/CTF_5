document.addEventListener('DOMContentLoaded', function() {
    const usernameInput = document.getElementById('reg-username');
    const emailInput = document.getElementById('reg-email');
    const passwordInput = document.getElementById('reg-password');
    const confirmInput = document.getElementById('reg-confirm');
    
    // Валидация username
    if (usernameInput) {
        usernameInput.addEventListener('blur', function() {
            const username = this.value.trim();
            if (username.length < 3) {
                showValidationMessage(this, 'Имя пользователя должно содержать минимум 3 символа');
                this.style.borderColor = 'var(--accent-color)';
                return;
            }
            checkUsernameAvailability(username);
        });
    }
    
    // Валидация email
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            const email = this.value.trim();
            if (!isValidEmail(email)) {
                showValidationMessage(this, 'Введите корректный email адрес');
                this.style.borderColor = 'var(--accent-color)';
                return;
            }
            checkEmailAvailability(email);
        });
    }
    
    // Валидация пароля
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            if (password.length > 0 && password.length < 6) {
                showValidationMessage(this, 'Пароль должен содержать минимум 6 символов');
                this.style.borderColor = 'var(--accent-color)';
            } else if (password.length >= 6) {
                hideValidationMessage(this);
                this.style.borderColor = 'var(--primary-color)';
            }
        });
    }
    
    // Подтверждение пароля
    if (confirmInput && passwordInput) {
        confirmInput.addEventListener('input', function() {
            const password = passwordInput.value;
            const confirm = this.value;
            
            if (confirm.length > 0 && password !== confirm) {
                showValidationMessage(this, 'Пароли не совпадают');
                this.style.borderColor = 'var(--accent-color)';
            } else if (password === confirm && confirm.length >= 6) {
                hideValidationMessage(this);
                this.style.borderColor = 'var(--primary-color)';
            }
        });
    }
    
    // Предотвращение отправки формы при ошибках
    const registerForm = document.querySelector('form[th\\:action="@{/register}"]');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            let hasErrors = false;
            
            // Проверка username
            const username = usernameInput.value.trim();
            if (username.length < 3) {
                showValidationMessage(usernameInput, 'Имя пользователя должно содержать минимум 3 символа');
                usernameInput.style.borderColor = 'var(--accent-color)';
                hasErrors = true;
            }
            
            // Проверка email
            const email = emailInput.value.trim();
            if (!isValidEmail(email)) {
                showValidationMessage(emailInput, 'Введите корректный email адрес');
                emailInput.style.borderColor = 'var(--accent-color)';
                hasErrors = true;
            }
            
            // Проверка пароля
            const password = passwordInput.value;
            if (password.length < 6) {
                showValidationMessage(passwordInput, 'Пароль должен содержать минимум 6 символов');
                passwordInput.style.borderColor = 'var(--accent-color)';
                hasErrors = true;
            }
            
            // Проверка подтверждения пароля
            if (password !== confirmInput.value) {
                showValidationMessage(confirmInput, 'Пароли не совпадают');
                confirmInput.style.borderColor = 'var(--accent-color)';
                hasErrors = true;
            }
            
            if (hasErrors) {
                e.preventDefault();
                // Прокрутка к первой ошибке
                const firstError = document.querySelector('.validation-message');
                if (firstError) {
                    firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }
        });
    }
});

function checkUsernameAvailability(username) {
    if (username.length < 3) return;
    
    fetch(`/check-username?username=${encodeURIComponent(username)}`)
        .then(response => {
            if (!response.ok) throw new Error('Network error');
            return response.text();
        })
        .then(result => {
            const input = document.getElementById('reg-username');
            if (result === 'exists') {
                input.style.borderColor = 'var(--accent-color)';
                showValidationMessage(input, 'Имя пользователя уже занято');
            } else {
                input.style.borderColor = 'var(--primary-color)';
                hideValidationMessage(input);
            }
        })
        .catch(error => {
            console.error('Error checking username:', error);
        });
}

function checkEmailAvailability(email) {
    if (!isValidEmail(email)) return;
    
    fetch(`/check-email?email=${encodeURIComponent(email)}`)
        .then(response => {
            if (!response.ok) throw new Error('Network error');
            return response.text();
        })
        .then(result => {
            const input = document.getElementById('reg-email');
            if (result === 'exists') {
                input.style.borderColor = 'var(--accent-color)';
                showValidationMessage(input, 'Email уже используется');
            } else {
                input.style.borderColor = 'var(--primary-color)';
                hideValidationMessage(input);
            }
        })
        .catch(error => {
            console.error('Error checking email:', error);
        });
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showValidationMessage(input, message) {
    let messageElement = input.parentNode.querySelector('.validation-message');
    if (!messageElement) {
        messageElement = document.createElement('div');
        messageElement.className = 'validation-message';
        messageElement.style.color = 'var(--accent-color)';
        messageElement.style.fontSize = '0.8rem';
        messageElement.style.marginTop = '0.3rem';
        messageElement.style.fontWeight = '500';
        input.parentNode.appendChild(messageElement);
    }
    messageElement.textContent = message;
    messageElement.style.display = 'block';
}

function hideValidationMessage(input) {
    const messageElement = input.parentNode.querySelector('.validation-message');
    if (messageElement) {
        messageElement.style.display = 'none';
    }
}