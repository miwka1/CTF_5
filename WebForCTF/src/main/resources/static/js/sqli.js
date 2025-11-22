/**
 * SQL Injection Challenge JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log('SQL Injection Challenge initialized');
    initializeLoginForm();
    initializeFlagCheckModal();
});

function initializeLoginForm() {
    const loginForm = document.getElementById('loginForm');
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleLogin();
        });
    }
}

function initializeFlagCheckModal() {
    // Закрытие модального окна при клике вне его
    const modal = document.getElementById('flagCheckModal');
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            closeFlagCheckModal();
        }
    });

    // Обработка нажатия Enter в поле ввода флага
    const flagInput = document.getElementById('flagInput');
    if (flagInput) {
        flagInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                validateFlag();
            }
        });
    }
}

function openFlagCheckModal() {
    const modal = document.getElementById('flagCheckModal');
    const flagInput = document.getElementById('flagInput');
    const resultDiv = document.getElementById('flagCheckResult');
    
    // Сбрасываем состояние
    flagInput.value = '';
    resultDiv.innerHTML = '';
    resultDiv.className = 'flag-check-result';
    
    // Показываем модальное окно
    modal.style.display = 'block';
    
    // Фокусируемся на поле ввода
    setTimeout(() => {
        flagInput.focus();
    }, 100);
}

function closeFlagCheckModal() {
    const modal = document.getElementById('flagCheckModal');
    modal.style.display = 'none';
}

function validateFlag() {
    const flagInput = document.getElementById('flagInput');
    const resultDiv = document.getElementById('flagCheckResult');
    const userFlag = flagInput.value.trim();

    if (!userFlag) {
        resultDiv.innerHTML = '❌ Введите флаг для проверки';
        resultDiv.className = 'flag-check-result error';
        return;
    }

    // Показываем загрузку
    resultDiv.innerHTML = '🔍 Проверяем флаг...';
    resultDiv.className = 'flag-check-result';

    // Отправляем запрос на сервер для проверки флага
    fetch('/challenges/sqli/validate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `flag=${encodeURIComponent(userFlag)}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            resultDiv.innerHTML = '✅ Правильно! Флаг принят.';
            resultDiv.className = 'flag-check-result success';
            celebrateFlagSuccess();
        } else {
            resultDiv.innerHTML = '❌ Неверный флаг. Попробуйте еще раз.';
            resultDiv.className = 'flag-check-result error';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        resultDiv.innerHTML = '⚠️ Ошибка проверки флага';
        resultDiv.className = 'flag-check-result error';
    });
}

function handleLogin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');
    
    // Показываем загрузку
    messageDiv.innerHTML = '<div class="success">🔐 Проверяем credentials...</div>';
    
    fetch('/challenges/sqli/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Автоматически показываем флаг при успешной SQL инъекции
            messageDiv.innerHTML = `
                <div class="success">
                    ✅ ${data.message}<br><br>
                    🎉 Задание выполнено!<br>
                    <strong>Флаг:</strong> 
                    <div class="flag-text">${data.flag}</div>
                    <small style="color: #888; margin-top: 10px; display: block;">
                        Скопируйте флаг и проверьте его через кнопку "Проверить флаг"
                    </small>
                </div>
            `;
            celebrateSuccess();
            logSuccess(username);
        } else {
            messageDiv.innerHTML = `<div class="error">❌ ${data.message}</div>`;
            logFailedAttempt(username);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        messageDiv.innerHTML = '<div class="error">⚠️ Ошибка соединения с сервером</div>';
    });
}

function celebrateFlagSuccess() {
    // Анимация успеха для флага
    createConfetti();
    
    // Автоматически закрываем окно через 2 секунды
    setTimeout(() => {
        closeFlagCheckModal();
    }, 2000);
}

function celebrateSuccess() {
    // Анимация успеха для всего контейнера
    const loginForm = document.querySelector('.login-form');
    loginForm.classList.add('celebrate');
    
    setTimeout(() => {
        loginForm.classList.remove('celebrate');
    }, 500);
    
    // Запускаем конфетти
    createConfetti();
}

function createConfetti() {
    const colors = ['#00ff88', '#ff4444', '#4488ff', '#ffff00', '#ff00ff'];
    
    for (let i = 0; i < 25; i++) {
        setTimeout(() => {
            const confetti = document.createElement('div');
            confetti.style.cssText = `
                position: fixed;
                width: 10px;
                height: 10px;
                background: ${colors[Math.floor(Math.random() * colors.length)]};
                top: -10px;
                left: ${Math.random() * 100}%;
                animation: confettiFall ${Math.random() * 2 + 1}s linear forwards;
                pointer-events: none;
                z-index: 1000;
                border-radius: 2px;
            `;
            
            document.body.appendChild(confetti);
            
            setTimeout(() => {
                confetti.remove();
            }, 2000);
        }, i * 80);
    }
}

function logSuccess(username) {
    console.log(`SQL Injection successful with username: ${username}`);
}

function logFailedAttempt(username) {
    console.log(`Failed login attempt: ${username}`);
}

// Добавляем стили для конфетти
const confettiStyles = document.createElement('style');
confettiStyles.textContent = `
    @keyframes confettiFall {
        0% {
            transform: translateY(0) rotate(0deg);
            opacity: 1;
        }
        100% {
            transform: translateY(100vh) rotate(360deg);
            opacity: 0;
        }
    }
`;
document.head.appendChild(confettiStyles);

// Экспорт для тестирования
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        handleLogin,
        validateFlag,
        openFlagCheckModal,
        closeFlagCheckModal
    };
}