/**
 * Web Challenges JavaScript functionality
 * Handles challenge modals, filtering, and interactions
 */

// Глобальные переменные для управления состоянием
let currentChallenge = null;
const challengeFlags = {
    'sqli': 'flag{sql_injection_success}',
    'xss': 'flag{xss_successful}',
    'auth': 'flag{auth_bypass_success}',
    'path': 'flag{path_traversal_success}',
    'csrf': 'flag{csrf_attack_success}'
};

// Инициализация при загрузке DOM
document.addEventListener('DOMContentLoaded', function() {
    console.log('Web Challenges initialized');
    initializeChallengeModals();
    initializeTaskFilters();
    initializeHints();
    ensureFooterPosition(); // Гарантируем правильное положение футера
});

// Инициализация модальных окон
function initializeChallengeModals() {
    const modal = document.getElementById('challengeModal');
    const closeBtn = document.querySelector('.close');
    
    if (closeBtn) {
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
            currentChallenge = null;
        });
    }
    
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
            currentChallenge = null;
        }
    });
}

// Инициализация фильтров заданий
function initializeTaskFilters() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Убираем активный класс у всех кнопок
            filterButtons.forEach(btn => btn.classList.remove('active'));
            // Добавляем активный класс текущей кнопке
            this.classList.add('active');
            
            const filter = this.getAttribute('data-filter');
            filterTasks(filter);
        });
    });
}

// Фильтрация заданий по сложности
function filterTasks(difficulty) {
    const tasks = document.querySelectorAll('.task-card');
    const tasksList = document.querySelector('.tasks-list');
    let visibleCount = 0;
    
    // Создаем сообщение для пустого состояния, если его нет
    let noTasksMessage = document.querySelector('.no-tasks-message');
    if (!noTasksMessage) {
        noTasksMessage = document.createElement('div');
        noTasksMessage.className = 'no-tasks-message hidden';
        noTasksMessage.textContent = 'No challenges found for this difficulty level';
        tasksList.appendChild(noTasksMessage);
    }
    
    tasks.forEach(task => {
        if (difficulty === 'all' || task.getAttribute('data-difficulty') === difficulty) {
            task.style.display = 'block';
            task.style.animation = `challengeFadeIn 0.5s ease-out ${visibleCount * 0.1}s both`;
            visibleCount++;
        } else {
            task.style.display = 'none';
        }
    });
    
    // Показываем/скрываем сообщение о пустом состоянии
    if (visibleCount === 0) {
        noTasksMessage.classList.remove('hidden');
    } else {
        noTasksMessage.classList.add('hidden');
    }
    
    console.log(`Filtered tasks: ${visibleCount} visible with filter '${difficulty}'`);
    
    // Обновляем положение футера после фильтрации
    setTimeout(ensureFooterPosition, 100);
}

// Гарантирует правильное положение футера
function ensureFooterPosition() {
    const container = document.querySelector('.container');
    const tasksSection = document.querySelector('.tasks-section');
    const footer = document.querySelector('.footer');
    
    if (container && tasksSection && footer) {
        const containerHeight = container.scrollHeight;
        const windowHeight = window.innerHeight;
        
        // Если контент меньше высоты окна, футер прижимается к низу
        if (containerHeight < windowHeight) {
            footer.style.marginTop = 'auto';
        } else {
            footer.style.marginTop = '40px'; // Нормальный отступ когда контента много
        }
    }
}

// Инициализация системы подсказок
function initializeHints() {
    // Добавляем обработчики для всех кнопок подсказок
    const hintButtons = document.querySelectorAll('.hint-btn');
    hintButtons.forEach(button => {
        const challengeType = button.getAttribute('onclick').match(/showHint\('(.+?)'\)/)[1];
        button.setAttribute('data-hint', challengeType);
        button.addEventListener('click', function() {
            showHint(challengeType);
        });
    });
}

// Функции для работы с заданиями
function openChallenge(challengeType) {
    const modal = document.getElementById('challengeModal');
    const content = document.getElementById('challengeContent');
    
    currentChallenge = challengeType;
    
    // Загружаем соответствующее задание
    let challengeHTML = '';
    
    switch(challengeType) {
        case 'sqli':
            challengeHTML = getSQLiChallenge();
            break;
        case 'xss':
            challengeHTML = getXSSChallenge();
            break;
        case 'auth':
            challengeHTML = getAuthChallenge();
            break;
        case 'path':
            challengeHTML = getPathChallenge();
            break;
        case 'csrf':
            challengeHTML = getCSRFChallenge();
            break;
        default:
            challengeHTML = '<p>Challenge not found</p>';
    }
    
    content.innerHTML = challengeHTML;
    modal.style.display = 'block';
    
    // Логируем открытие задания
    console.log(`Challenge opened: ${challengeType}`);
}

function showHint(hintId) {
    const hint = document.getElementById(hintId);
    if (hint) {
        if (hint.style.display === 'none' || !hint.style.display) {
            hint.style.display = 'block';
            hint.style.animation = 'challengeFadeIn 0.3s ease-out';
            console.log(`Hint shown: ${hintId}`);
        } else {
            hint.style.display = 'none';
        }
    }
}

// Функции для генерации контента заданий
function getSQLiChallenge() {
    return `
        <h2>SQL Injection Challenge</h2>
        <p>Войдите в систему как администратор, используя SQL инъекцию</p>
        
        <div class="challenge-frame" id="sqliFrame">
            <iframe src="/challenges/sqli" style="width:100%; height:100%; border:none;"></iframe>
        </div>
        
        <div class="challenge-controls">
            <input type="text" class="flag-input" id="sqliFlag" placeholder="Введите флаг">
            <button class="challenge-btn" onclick="checkFlag('sqli')">Submit Flag</button>
        </div>
        <div id="sqliResult"></div>
    `;
}

function getXSSChallenge() {
    return `
        <h2>XSS Challenge</h2>
        <p>Внедрите XSS скрипт, который выполнится на странице</p>
        
        <div class="challenge-frame" id="xssFrame">
            <iframe src="/challenges/xss" style="width:100%; height:100%; border:none;"></iframe>
        </div>
        
        <div class="challenge-controls">
            <input type="text" class="flag-input" id="xssFlag" placeholder="Введите флаг">
            <button class="challenge-btn" onclick="checkFlag('xss')">Submit Flag</button>
        </div>
        <div id="xssResult"></div>
    `;
}

function getAuthChallenge() {
    return `
        <h2>Authentication Bypass Challenge</h2>
        <p>Обойдите аутентификацию и получите доступ к защищенной странице</p>
        
        <div class="challenge-frame" id="authFrame">
            <iframe src="/challenges/auth" style="width:100%; height:100%; border:none;"></iframe>
        </div>
        
        <div class="challenge-controls">
            <input type="text" class="flag-input" id="authFlag" placeholder="Введите флаг">
            <button class="challenge-btn" onclick="checkFlag('auth')">Submit Flag</button>
        </div>
        <div id="authResult"></div>
    `;
}

function getPathChallenge() {
    return `
        <h2>Path Traversal Challenge</h2>
        <p>Используйте уязвимость Path Traversal для чтения файла /flag.txt</p>
        
        <div class="challenge-frame" id="pathFrame">
            <iframe src="/challenges/path" style="width:100%; height:100%; border:none;"></iframe>
        </div>
        
        <div class="challenge-controls">
            <input type="text" class="flag-input" id="pathFlag" placeholder="Введите флаг">
            <button class="challenge-btn" onclick="checkFlag('path')">Submit Flag</button>
        </div>
        <div id="pathResult"></div>
    `;
}

function getCSRFChallenge() {
    return `
        <h2>CSRF Challenge</h2>
        <p>Создайте CSRF атаку для изменения email администратора</p>
        
        <div class="challenge-frame" id="csrfFrame">
            <iframe src="/challenges/csrf" style="width:100%; height:100%; border:none;"></iframe>
        </div>
        
        <div class="challenge-controls">
            <input type="text" class="flag-input" id="csrfFlag" placeholder="Введите флаг">
            <button class="challenge-btn" onclick="checkFlag('csrf')">Submit Flag</button>
        </div>
        <div id="csrfResult"></div>
    `;
}

// Функция проверки флага
function checkFlag(challengeType) {
    const flagInput = document.getElementById(`${challengeType}Flag`);
    const resultDiv = document.getElementById(`${challengeType}Result`);
    
    if (!flagInput || !resultDiv) {
        console.error('Flag input or result div not found');
        return;
    }
    
    const userFlag = flagInput.value.trim();
    const correctFlag = challengeFlags[challengeType];
    
    if (userFlag === correctFlag) {
        resultDiv.innerHTML = '<p class="success-message">✅ Правильно! Флаг принят.</p>';
        resultDiv.style.animation = 'challengeFadeIn 0.5s ease-out';
        
        // Логируем успешное решение
        console.log(`Challenge ${challengeType} solved with flag: ${userFlag}`);
        
        // Можно добавить отправку на сервер здесь
        submitFlagToServer(challengeType, userFlag);
    } else {
        resultDiv.innerHTML = '<p class="error-message">❌ Неверный флаг. Попробуйте еще раз.</p>';
        resultDiv.style.animation = 'challengeFadeIn 0.3s ease-out';
        
        console.log(`Failed attempt for ${challengeType}: ${userFlag}`);
    }
}

// Заглушка для отправки флага на сервер
function submitFlagToServer(challengeType, flag) {
    // В реальной системе здесь был бы fetch запрос к серверу
    console.log(`Submitting flag to server: ${challengeType} - ${flag}`);
}

// Обработчик изменения размера окна для корректного положения футера
window.addEventListener('resize', debounce(ensureFooterPosition, 250));

// Утилиты
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Экспорт для тестирования
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        initializeChallengeModals,
        filterTasks,
        checkFlag,
        challengeFlags,
        ensureFooterPosition
    };
}