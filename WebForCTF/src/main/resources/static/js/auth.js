document.addEventListener('DOMContentLoaded', function() {
    
    const confirmPassword = document.getElementById('reg-confirm');
    const password = document.getElementById('reg-password');
    
    if (confirmPassword && password) {
        confirmPassword.addEventListener('input', function() {
            if (password.value !== confirmPassword.value) {
                this.style.borderColor = 'var(--accent-color)';
                this.style.boxShadow = '0 0 10px rgba(255, 0, 136, 0.3)';
            } else {
                this.style.borderColor = 'var(--primary-color)';
                this.style.boxShadow = '0 0 10px rgba(0, 255, 136, 0.3)';
            }
        });
    }
    
    
    const authButtons = document.querySelectorAll('.auth-btn');
    authButtons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});