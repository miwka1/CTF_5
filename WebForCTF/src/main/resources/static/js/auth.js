/**
 * CTF Platform - Authentication Logic
 * Логика аутентификации и регистрации
 */

class CTFAuth {
    constructor() {
        this.init();
    }

    init() {
        this.initFormValidation();
        this.initRealTimeValidation();
        this.initPasswordStrength();
        this.initOAuthHandlers();
    }

    initFormValidation() {
        const form = document.getElementById('authForm');
        if (!form) return;

        form.addEventListener('submit', (e) => {
            if (!this.validateForm(form)) {
                e.preventDefault();
            }
        });
    }

    initRealTimeValidation() {
        const usernameInput = document.querySelector('input[name="username"]');
        const emailInput = document.querySelector('input[name="email"]');
        const passwordInput = document.querySelector('input[name="password"]');
        const confirmInput = document.querySelector('input[name="confirmPassword"]');

        if (usernameInput) {
            usernameInput.addEventListener('input', (e) => {
                this.validateUsername(e.target.value);
            });
        }

        if (emailInput) {
            emailInput.addEventListener('input', (e) => {
                this.validateEmail(e.target.value);
            });
        }

        if (passwordInput && confirmInput) {
            passwordInput.addEventListener('input', () => {
                this.validatePasswordMatch(passwordInput.value, confirmInput.value);
            });
            confirmInput.addEventListener('input', () => {
                this.validatePasswordMatch(passwordInput.value, confirmInput.value);
            });
        }
    }

    initPasswordStrength() {
        const passwordInput = document.querySelector('input[name="password"]');
        if (!passwordInput) return;

        passwordInput.addEventListener('input', (e) => {
            this.updatePasswordStrength(e.target.value);
        });
    }

    initOAuthHandlers() {
        // Добавляем обработчики для красивого эффекта
        const oauthButtons = document.querySelectorAll('.oauth-btn');
        oauthButtons.forEach(btn => {
            btn.addEventListener('mouseenter', this.addRippleEffect.bind(this));
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const provider = btn.classList.contains('github-btn') ? 'GitHub' : 'Google';
                this.showOAuthMessage(provider);
            });
        });
    }

    addRippleEffect(e) {
        const btn = e.currentTarget;
        const ripple = document.createElement('span');
        const rect = btn.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;

        ripple.style.cssText = `
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: scale(0);
            animation: ripple 0.6s linear;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            pointer-events: none;
        `;

        // Добавляем стили для анимации
        if (!document.querySelector('#ripple-styles')) {
            const style = document.createElement('style');
            style.id = 'ripple-styles';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }

        btn.appendChild(ripple);
        setTimeout(() => ripple.remove(), 600);
    }

    validateForm(form) {
        const username = form.querySelector('input[name="username"]');
        const email = form.querySelector('input[name="email"]');
        const password = form.querySelector('input[name="password"]');
        const confirmPassword = form.querySelector('input[name="confirmPassword"]');

        let isValid = true;

        if (username && !this.validateUsername(username.value)) {
            this.showValidationMessage(username, 'Invalid username');
            isValid = false;
        }

        if (email && !this.validateEmail(email.value)) {
            this.showValidationMessage(email, 'Invalid email address');
            isValid = false;
        }

        if (password && password.value.length < 6) {
            this.showValidationMessage(password, 'Password must be at least 6 characters');
            isValid = false;
        }

        if (confirmPassword && password && password.value !== confirmPassword.value) {
            this.showValidationMessage(confirmPassword, 'Passwords do not match');
            isValid = false;
        }

        return isValid;
    }

    validateUsername(username) {
        const validationElement = document.getElementById('usernameValidation');
        if (!validationElement) return true;

        if (username.length < 3) {
            this.showValidationMessage(null, 'Username must be at least 3 characters', 'usernameValidation', 'invalid');
            return false;
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            this.showValidationMessage(null, 'Username can only contain letters, numbers and underscores', 'usernameValidation', 'invalid');
            return false;
        }

        this.showValidationMessage(null, 'Username is available', 'usernameValidation', 'valid');
        return true;
    }

    validateEmail(email) {
        const validationElement = document.getElementById('emailValidation');
        if (!validationElement) return true;

        if (!this.validateEmailFormat(email)) {
            this.showValidationMessage(null, 'Please enter a valid email address', 'emailValidation', 'invalid');
            return false;
        }

        this.showValidationMessage(null, 'Email is valid', 'emailValidation', 'valid');
        return true;
    }

    validateEmailFormat(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validatePasswordMatch(password, confirmPassword) {
        const validationElement = document.getElementById('confirmPasswordValidation');
        if (!validationElement || !confirmPassword) return;

        if (password !== confirmPassword) {
            this.showValidationMessage(null, 'Passwords do not match', 'confirmPasswordValidation', 'invalid');
        } else {
            this.showValidationMessage(null, 'Passwords match', 'confirmPasswordValidation', 'valid');
        }
    }

    updatePasswordStrength(password) {
        const strengthElement = document.getElementById('passwordStrength');
        if (!strengthElement) return;

        let strength = 0;
        let message = '';
        let color = '';

        if (password.length >= 6) strength++;
        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        switch (strength) {
            case 0:
            case 1:
                message = 'Very Weak';
                color = 'var(--error-color)';
                break;
            case 2:
                message = 'Weak';
                color = '#ff4444';
                break;
            case 3:
                message = 'Medium';
                color = '#ffa500';
                break;
            case 4:
                message = 'Strong';
                color = '#00ff88';
                break;
            case 5:
                message = 'Very Strong';
                color = 'var(--primary-color)';
                break;
        }

        strengthElement.textContent = `Password Strength: ${message}`;
        strengthElement.style.color = color;
        strengthElement.style.display = password ? 'block' : 'none';
    }

    showValidationMessage(inputElement, message, elementId = null, type = 'info') {
        let validationElement;

        if (elementId) {
            validationElement = document.getElementById(elementId);
        } else if (inputElement) {
            validationElement = inputElement.parentNode.querySelector('.validation-message');
            if (!validationElement) {
                validationElement = document.createElement('div');
                validationElement.className = 'validation-message';
                inputElement.parentNode.appendChild(validationElement);
            }
        }

        if (!validationElement) return;

        validationElement.textContent = message;
        validationElement.className = `validation-message ${type}`;
        validationElement.style.display = 'block';
    }

    // OAuth методы
    showOAuthMessage(provider) {
        this.createOAuthNotification(provider);
    }

    createOAuthNotification(provider) {
        // Удаляем существующие уведомления
        const existingNotification = document.querySelector('.oauth-notification');
        const existingOverlay = document.querySelector('.oauth-overlay');
        if (existingNotification) existingNotification.remove();
        if (existingOverlay) existingOverlay.remove();

        // Создаем overlay
        const overlay = document.createElement('div');
        overlay.className = 'oauth-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 10000;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease-out;
        `;

        // Создаем уведомление
        const notification = document.createElement('div');
        notification.className = 'oauth-notification';
        notification.style.cssText = `
            background: linear-gradient(135deg, rgba(26, 26, 26, 0.95), rgba(40, 40, 40, 0.95));
            border: 2px solid var(--primary-color);
            border-radius: 20px;
            padding: 3rem 2rem;
            max-width: 500px;
            width: 90%;
            text-align: center;
            backdrop-filter: blur(20px);
            box-shadow: 0 25px 80px rgba(0, 255, 136, 0.3);
            animation: slideInUp 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            position: relative;
            overflow: hidden;
        `;

        // Добавляем градиентный фон
        notification.innerHTML = `
            <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(circle at 30% 20%, rgba(0, 255, 136, 0.1), transparent 50%), radial-gradient(circle at 70% 80%, rgba(0, 136, 255, 0.1), transparent 50%); pointer-events: none;"></div>

            <div style="position: relative; z-index: 2;">
                <div style="font-size: 4rem; margin-bottom: 1.5rem; animation: bounce 2s infinite;">🚧</div>

                <h3 style="margin-bottom: 1rem; color: var(--primary-color); font-family: 'Orbitron', sans-serif; font-size: 1.8rem; text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);">
                    ${provider} Authentication
                </h3>

                <p style="margin-bottom: 2rem; color: var(--text-secondary); line-height: 1.6; font-size: 1.1rem;">
                    Secure OAuth 2.0 integration is coming in the next update!
                </p>

                <div style="background: rgba(0, 255, 136, 0.1); border: 1px solid var(--primary-color); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; backdrop-filter: blur(10px);">
                    <h4 style="margin-bottom: 1rem; color: var(--primary-color); font-family: 'Orbitron', sans-serif;">Coming Features:</h4>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; text-align: left; color: var(--text-primary);">
                        <div>🔐 One-click login</div>
                        <div>🔄 Profile sync</div>
                        <div>🔒 Enhanced security</div>
                        <div>⚡ Faster access</div>
                    </div>
                </div>

                <button class="close-oauth-btn"
                        style="background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
                               color: #000;
                               border: none;
                               padding: 1rem 2.5rem;
                               border-radius: 12px;
                               font-weight: bold;
                               cursor: pointer;
                               font-family: 'Roboto', sans-serif;
                               font-size: 1rem;
                               transition: all 0.3s ease;
                               box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);">
                    Continue with Email
                </button>
            </div>
        `;

        // Добавляем стили для анимации
        if (!document.querySelector('#oauth-styles')) {
            const style = document.createElement('style');
            style.id = 'oauth-styles';
            style.textContent = `
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }

                @keyframes slideInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px) scale(0.9);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0) scale(1);
                    }
                }

                @keyframes bounce {
                    0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
                    40% { transform: translateY(-10px); }
                    60% { transform: translateY(-5px); }
                }

                .close-oauth-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 25px rgba(0, 255, 136, 0.5);
                }

                .close-oauth-btn:active {
                    transform: translateY(0);
                }
            `;
            document.head.appendChild(style);
        }

        // Обработчик закрытия
        const closeHandler = () => {
            notification.style.animation = 'slideInUp 0.3s ease-out reverse';
            overlay.style.animation = 'fadeIn 0.3s ease-out reverse';
            setTimeout(() => {
                overlay.remove();
            }, 300);
        };

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeHandler();
        });

        const closeBtn = notification.querySelector('.close-oauth-btn');
        closeBtn.addEventListener('click', closeHandler);

        document.body.appendChild(overlay);
        overlay.appendChild(notification);

        // Автоматическое закрытие через 6 секунд
        setTimeout(closeHandler, 6000);
    }
}

// Глобальная функция для OAuth кнопок
function showOAuthMessage(provider) {
    if (window.ctfAuth) {
        window.ctfAuth.showOAuthMessage(provider);
    }
}

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/auth' || window.location.pathname.includes('/auth')) {
        window.ctfAuth = new CTFAuth();
    }
});