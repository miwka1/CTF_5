/**
 * CTF Platform - CSRF Challenge
 * Логика для CSRF челленджа
 */

class CSRFChallenge {
    constructor() {
        this.balance = 1000;
        this.transactions = [];
        this.csrfToken = CTFUtils.randomString(32);
        this.init();
    }

    init() {
        this.initEventListeners();
        this.updateBalanceDisplay();
        this.loadTransactionHistory();
        this.createMaliciousPage();
    }

    initEventListeners() {
        const transferBtn = document.querySelector('button[onclick="transferFunds()"]');
        if (transferBtn) {
            transferBtn.addEventListener('click', () => {
                this.transferFunds();
            });
        }
    }

    transferFunds() {
        const amountInput = document.getElementById('amount');
        const targetInput = document.getElementById('targetAccount');

        if (!amountInput || !targetInput) return;

        const amount = parseInt(amountInput.value);
        const targetAccount = targetInput.value.trim();

        if (!amount || amount <= 0) {
            CTFPlatform.showNotification('Please enter a valid amount', 'error');
            return;
        }

        if (!targetAccount) {
            CTFPlatform.showNotification('Please enter target account', 'error');
            return;
        }

        if (amount > this.balance) {
            CTFPlatform.showNotification('Insufficient funds', 'error');
            return;
        }

        // Проверяем CSRF токен (уязвимость - токен не проверяется)
        const token = document.querySelector('input[name="csrf_token"]')?.value;

        // Имитация успешного перевода
        this.balance -= amount;
        this.transactions.unshift({
            id: this.transactions.length + 1,
            type: 'debit',
            amount: amount,
            target: targetAccount,
            timestamp: new Date(),
            description: `Transfer to ${targetAccount}`
        });

        this.updateBalanceDisplay();
        this.updateTransactionHistory();

        amountInput.value = '';
        targetInput.value = '';

        CTFPlatform.showNotification(`Successfully transferred $${amount} to ${targetAccount}`, 'success');

        // Проверяем CSRF атаку
        this.checkCSRFAttack(targetAccount, amount);
    }

    updateBalanceDisplay() {
        const balanceElement = document.querySelector('.account-balance');
        if (balanceElement) {
            balanceElement.textContent = `$${this.balance}`;
        }
    }

    updateTransactionHistory() {
        const transactionList = document.querySelector('.transaction-list');
        if (!transactionList) return;

        transactionList.innerHTML = '';

        this.transactions.slice(0, 10).forEach(transaction => {
            const transactionElement = this.createTransactionElement(transaction);
            transactionList.appendChild(transactionElement);
        });
    }

    createTransactionElement(transaction) {
        const transactionDiv = document.createElement('div');
        transactionDiv.className = `transaction ${transaction.type}`;

        transactionDiv.innerHTML = `
            <div class="transaction-info">
                <div class="transaction-description">${CTFUtils.escapeHtml(transaction.description)}</div>
                <div class="transaction-time">${this.formatTime(transaction.timestamp)}</div>
            </div>
            <div class="transaction-amount ${transaction.type}">
                ${transaction.type === 'credit' ? '+' : '-'}$${transaction.amount}
            </div>
        `;

        return transactionDiv;
    }

    loadTransactionHistory() {
        // Загрузка истории транзакций
        this.transactions = [
            {
                id: 1,
                type: 'credit',
                amount: 1000,
                target: 'initial',
                timestamp: new Date('2024-01-01'),
                description: 'Initial deposit'
            }
        ];
        this.updateTransactionHistory();
    }

    formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString('ru-RU', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    checkCSRFAttack(targetAccount, amount) {
        // Проверяем, является ли это CSRF атакой
        if (targetAccount === 'attacker_account' && amount === 500) {
            CTFPlatform.showNotification('CSRF attack detected! Flag unlocked!', 'success');
            this.showFlag();
        }
    }

    showFlag() {
        const flag = 'CTF{CSRF_MASTER_2024}';
        const bankingInterface = document.querySelector('.banking-interface');
        if (!bankingInterface) return;

        const flagElement = document.createElement('div');
        flagElement.className = 'message success';
        flagElement.innerHTML = `
            🎉 CSRF Vulnerability Exploited!<br>
            <strong>Flag: ${flag}</strong><br>
            <small>Click to copy</small>
        `;

        flagElement.addEventListener('click', () => {
            CTFUtils.copyToClipboard(flag);
        });

        bankingInterface.appendChild(flagElement);

        CTFUtils.copyToClipboard(flag);
    }

    createMaliciousPage() {
        // Создаем демонстрационную вредоносную страницу для CSRF
        console.log('CSRF Token (for demonstration):', this.csrfToken);

        // В реальном приложении здесь бы создавалась отдельная страница
        // с формой, которая автоматически submits на эндпоинт перевода
    }

    // Метод для демонстрации CSRF уязвимости
    demonstrateCSRF() {
        const maliciousForm = `
            <form id="csrfForm" action="/api/transfer" method="POST" style="display: none;">
                <input type="hidden" name="amount" value="500">
                <input type="hidden" name="target" value="attacker_account">
                <input type="hidden" name="csrf_token" value="${this.csrfToken}">
            </form>
            <script>document.getElementById('csrfForm').submit();</script>
        `;

        console.log('Malicious CSRF form:', maliciousForm);
        CTFPlatform.showNotification('CSRF demonstration prepared. Check console.', 'info');
    }

    resetChallenge() {
        this.balance = 1000;
        this.transactions = [{
            id: 1,
            type: 'credit',
            amount: 1000,
            target: 'initial',
            timestamp: new Date(),
            description: 'Initial deposit'
        }];

        this.updateBalanceDisplay();
        this.updateTransactionHistory();

        CTFPlatform.showNotification('Banking interface reset', 'info');
    }
}

// Глобальная функция для обратной совместимости
function transferFunds() {
    if (window.csrfChallenge) {
        window.csrfChallenge.transferFunds();
    }
}

// Инициализация на странице CSRF
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('/csrf')) {
        window.csrfChallenge = new CSRFChallenge();
    }
});