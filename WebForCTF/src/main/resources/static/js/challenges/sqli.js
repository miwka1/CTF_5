/**
 * CTF Platform - SQL Injection Challenge
 * Логика для SQL Injection челленджа
 */

class SQLInjectionChallenge {
    constructor() {
        this.attempts = 0;
        this.maxAttempts = 10;
        this.isSolved = false;
        this.init();
    }

    init() {
        this.initEventListeners();
        this.loadChallengeInfo();
    }

    initEventListeners() {
        const loginForm = document.getElementById('loginForm');
        const hintButton = document.querySelector('.hint-button');
        const validateFlagBtn = document.getElementById('validateFlagBtn');
        const resetChallengeBtn = document.getElementById('resetChallengeBtn');
        // УДАЛЕНО: showSolutionBtn

        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        if (hintButton) {
            hintButton.addEventListener('click', () => {
                this.toggleHint();
            });
        }

        if (validateFlagBtn) {
            validateFlagBtn.addEventListener('click', () => {
                this.validateFlag();
            });
        }

        if (resetChallengeBtn) {
            resetChallengeBtn.addEventListener('click', () => {
                this.resetChallenge();
            });
        }

        // УДАЛЕНО: обработчик для showSolutionBtn
    }

    async loadChallengeInfo() {
        try {
            const response = await CTFUtils.fetchJSON('/challenges/sqli/info');
            this.updateChallengeUI(response);
        } catch (error) {
            console.error('Error loading challenge info:', error);
        }
    }

    updateChallengeUI(info) {
        const pointsBadge = document.querySelector('.points-badge');
        const difficultyBadge = document.querySelector('.difficulty-badge');

        if (pointsBadge && info.points) {
            pointsBadge.textContent = `${info.points} points`;
        }

        if (difficultyBadge && info.difficulty) {
            difficultyBadge.textContent = info.difficulty;
            difficultyBadge.className = `difficulty-badge ${info.difficulty}`;
        }
    }

    async handleLogin() {
        if (this.attempts >= this.maxAttempts) {
            this.showMessage('Too many attempts. Please wait before trying again.', 'error');
            return;
        }

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (!username || !password) {
            this.showMessage('Please enter both username and password', 'error');
            return;
        }

        this.attempts++;

        try {
            const response = await this.submitLogin(username, password);
            this.processLoginResponse(response);
        } catch (error) {
            console.error('Login error:', error);
            this.showMessage('Connection error. Please try again.', 'error');
        }
    }

    async submitLogin(username, password) {
        const response = await fetch('/challenges/sqli/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        });

        return await response.json();
    }

    processLoginResponse(response) {
        const messageElement = document.getElementById('message');

        if (response.success) {
            this.showMessage(response.message, 'success');
            this.showFlag(response.flag);
            this.isSolved = true;
            this.celebrateSuccess();
        } else {
            this.showMessage(response.message, 'error');
        }
    }

    showMessage(message, type) {
        const messageElement = document.getElementById('message');
        if (!messageElement) return;

        messageElement.textContent = message;
        messageElement.className = `message ${type}`;
        messageElement.style.display = 'block';

        // Авто-скрытие успешных сообщений
        if (type === 'success') {
            setTimeout(() => {
                messageElement.style.display = 'none';
            }, 5000);
        }
    }

    showFlag(flag) {
        const messageElement = document.getElementById('message');
        if (!messageElement) return;

        const flagElement = document.createElement('div');
        flagElement.className = 'flag-text';
        flagElement.textContent = `Flag: ${flag}`;
        flagElement.addEventListener('click', () => {
            CTFUtils.copyToClipboard(flag);
        });

        messageElement.appendChild(flagElement);
    }

    celebrateSuccess() {
        const loginForm = document.querySelector('.login-form');
        if (loginForm) {
            loginForm.classList.add('celebrate');
            setTimeout(() => {
                loginForm.classList.remove('celebrate');
            }, 500);
        }

        // Запускаем конфетти
        this.createConfetti();
    }

    createConfetti() {
        const colors = ['#00ff88', '#0088ff', '#ff0088', '#ffa500'];
        for (let i = 0; i < 50; i++) {
            setTimeout(() => {
                const confetti = document.createElement('div');
                confetti.style.cssText = `
                    position: fixed;
                    width: 10px;
                    height: 10px;
                    background: ${colors[Math.floor(Math.random() * colors.length)]};
                    border-radius: 50%;
                    top: -10px;
                    left: ${Math.random() * 100}%;
                    animation: confettiFall ${Math.random() * 3 + 2}s linear forwards;
                    z-index: 10000;
                    pointer-events: none;
                `;
                document.body.appendChild(confetti);

                setTimeout(() => {
                    confetti.remove();
                }, 3000);
            }, i * 100);
        }

        // Добавляем CSS анимацию
        if (!document.getElementById('confetti-style')) {
            const style = document.createElement('style');
            style.id = 'confetti-style';
            style.textContent = `
                @keyframes confettiFall {
                    to {
                        transform: translateY(100vh) rotate(360deg);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }

    toggleHint() {
        const hintContent = document.getElementById('hintContent');
        const hintButton = document.querySelector('.hint-button');

        if (hintContent && hintButton) {
            hintContent.classList.toggle('show');
            hintButton.textContent = hintContent.classList.contains('show') ?
                'Hide Hint' : 'Show Hint';
        }
    }

    async validateFlag() {
        const flagInput = document.getElementById('flagInput');
        const flagMessage = document.getElementById('flagMessage');

        if (!flagInput || !flagMessage) return;

        const flag = flagInput.value.trim();
        if (!flag) {
            this.showFlagMessage('Please enter a flag', 'error');
            return;
        }

        try {
            const response = await fetch('/challenges/sqli/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `flag=${encodeURIComponent(flag)}`
            });

            const result = await response.json();
            this.showFlagMessage(result.message, result.success ? 'success' : 'error');

            if (result.success) {
                flagInput.value = '';
                this.isSolved = true;
            }
        } catch (error) {
            console.error('Flag validation error:', error);
            this.showFlagMessage('Validation error. Please try again.', 'error');
        }
    }

    showFlagMessage(message, type) {
        const flagMessage = document.getElementById('flagMessage');
        if (!flagMessage) return;

        flagMessage.textContent = message;
        flagMessage.className = `message ${type}`;
        flagMessage.style.display = 'block';

        if (type === 'success') {
            setTimeout(() => {
                flagMessage.style.display = 'none';
            }, 5000);
        }
    }

    async getHint() {
        try {
            const response = await CTFUtils.fetchJSON('/challenges/sqli/hint');
            return response.hint;
        } catch (error) {
            console.error('Error getting hint:', error);
            return 'Hint not available';
        }
    }

    resetChallenge() {
        this.attempts = 0;
        this.isSolved = false;

        const forms = document.querySelectorAll('form');
        forms.forEach(form => form.reset());

        const messages = document.querySelectorAll('.message');
        messages.forEach(msg => {
            msg.style.display = 'none';
            msg.textContent = '';
        });

        const hintContent = document.getElementById('hintContent');
        if (hintContent) {
            hintContent.classList.remove('show');
        }

        const hintButton = document.querySelector('.hint-button');
        if (hintButton) {
            hintButton.textContent = 'Show Hint';
        }

        this.showMessage('Challenge has been reset', 'info');
    }

    // УДАЛЕН МЕТОД showSolution()
}

// Инициализация на странице SQL Injection
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('/sqli')) {
        window.sqliChallenge = new SQLInjectionChallenge();
    }
});